terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = "us-east-1"
}

data "aws_caller_identity" "current" {}

# ── IAM ROLE for Config ───────────────────────────────────
resource "aws_iam_role" "config_role" {
  name = "AWSConfigRole"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "config.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "config_role" {
  role       = aws_iam_role.config_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWS_ConfigRole"
}

# ── S3 BUCKET for Config logs ─────────────────────────────
resource "aws_s3_bucket" "config_logs" {
  bucket        = "fintech-config-logs-${data.aws_caller_identity.current.account_id}"
  force_destroy = true
  tags = {
    Project = "FinTech-Capstone"
  }
}

resource "aws_s3_bucket_public_access_block" "config_logs" {
  bucket                  = aws_s3_bucket.config_logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_policy" "config_logs" {
  bucket     = aws_s3_bucket.config_logs.id
  depends_on = [aws_s3_bucket_public_access_block.config_logs]

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AWSConfigBucketPermissionsCheck"
        Effect = "Allow"
        Principal = { Service = "config.amazonaws.com" }
        Action   = "s3:GetBucketAcl"
        Resource = "arn:aws:s3:::fintech-config-logs-${data.aws_caller_identity.current.account_id}"
      },
      {
        Sid    = "AWSConfigBucketDelivery"
        Effect = "Allow"
        Principal = { Service = "config.amazonaws.com" }
        Action   = "s3:PutObject"
        Resource = "arn:aws:s3:::fintech-config-logs-${data.aws_caller_identity.current.account_id}/AWSLogs/${data.aws_caller_identity.current.account_id}/Config/*"
        Condition = {
          StringEquals = { "s3:x-amz-acl" = "bucket-owner-full-control" }
        }
      }
    ]
  })
}

# ── AWS CONFIG RECORDER ───────────────────────────────────
resource "aws_config_configuration_recorder" "main" {
  name     = "fintech-config-recorder"
  role_arn = aws_iam_role.config_role.arn

  recording_group {
    all_supported                 = true
    include_global_resource_types = true
  }
}

resource "aws_config_delivery_channel" "main" {
  name           = "fintech-config-delivery"
  s3_bucket_name = aws_s3_bucket.config_logs.bucket
  depends_on     = [aws_config_configuration_recorder.main]
}

resource "aws_config_configuration_recorder_status" "main" {
  name       = aws_config_configuration_recorder.main.name
  is_enabled = true
  depends_on = [aws_config_delivery_channel.main]
}

# ── CONFIG RULE: S3 Encryption ────────────────────────────
resource "aws_config_config_rule" "s3_encryption" {
  name        = "s3-bucket-server-side-encryption-enabled"
  description = "Checks if S3 buckets have server-side encryption enabled"

  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_SERVER_SIDE_ENCRYPTION_ENABLED"
  }

  depends_on = [aws_config_configuration_recorder_status.main]
}

# ── AUTO REMEDIATION for S3 Encryption ───────────────────
resource "aws_config_remediation_configuration" "s3_encryption" {
  config_rule_name = aws_config_config_rule.s3_encryption.name
  target_type      = "SSM_DOCUMENT"
  target_id        = "AWS-EnableS3BucketEncryption"
  automatic        = true

  parameter {
    name         = "AutomationAssumeRole"
    static_value = aws_iam_role.remediation_role.arn
  }

  parameter {
    name         = "BucketName"
    resource_value = "RESOURCE_ID"
  }

  parameter {
    name         = "SSEAlgorithm"
    static_value = "aws:kms"
  }

  maximum_automatic_attempts = 3
  retry_attempt_seconds      = 60

  execution_controls {
    ssm_controls {
      concurrent_execution_rate_percentage = 25
      error_percentage                     = 20
    }
  }

  depends_on = [aws_config_config_rule.s3_encryption]
}

# ── IAM ROLE for Auto Remediation ────────────────────────
resource "aws_iam_role" "remediation_role" {
  name = "ConfigRemediationRole"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ssm.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "remediation_role" {
  name = "ConfigRemediationPolicy"
  role = aws_iam_role.remediation_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:PutEncryptionConfiguration",
          "s3:GetEncryptionConfiguration",
          "s3:ListAllMyBuckets"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "kms:DescribeKey",
          "kms:ListKeys"
        ]
        Resource = "*"
      }
    ]
  })
}

# ── SECURITY HUB ──────────────────────────────────────────
resource "aws_securityhub_account" "main" {}

# ── Enable GuardDuty integration with Security Hub ────────
resource "aws_securityhub_product_subscription" "guardduty" {
  product_arn = "arn:aws:securityhub:us-east-1::product/aws/guardduty"
  depends_on  = [aws_securityhub_account.main]
}

# ── Enable Config integration with Security Hub ───────────
resource "aws_securityhub_product_subscription" "config" {
  product_arn = "arn:aws:securityhub:us-east-1::product/aws/config"
  depends_on  = [aws_securityhub_account.main]
}

# ── EVENTBRIDGE: High findings → SNS ─────────────────────
resource "aws_cloudwatch_event_rule" "security_hub_high" {
  name        = "SecurityHubHighFindings"
  description = "Routes high severity Security Hub findings to SNS"

  event_pattern = jsonencode({
    source      = ["aws.securityhub"]
    detail-type = ["Security Hub Findings - Imported"]
    detail = {
      findings = {
        Severity = {
          Label = ["HIGH", "CRITICAL"]
        }
      }
    }
  })
}

resource "aws_cloudwatch_event_target" "security_hub_sns" {
  rule = aws_cloudwatch_event_rule.security_hub_high.name
  arn  = "arn:aws:sns:us-east-1:430287290736:fintech-security-alerts"
}

resource "aws_sns_topic_policy" "security_hub" {
  arn = "arn:aws:sns:us-east-1:430287290736:fintech-security-alerts"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "AllowEventBridge"
      Effect = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action   = "sns:Publish"
      Resource = "arn:aws:sns:us-east-1:430287290736:fintech-security-alerts"
    }]
  })
}

# ── OUTPUTS ───────────────────────────────────────────────
output "config_bucket" {
  value = aws_s3_bucket.config_logs.bucket
}

output "config_rule_name" {
  value = aws_config_config_rule.s3_encryption.name
}

output "security_hub_enabled" {
  value = "Security Hub enabled with Foundational Best Practices"
}