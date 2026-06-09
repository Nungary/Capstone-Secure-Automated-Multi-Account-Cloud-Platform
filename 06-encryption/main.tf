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

# ── KMS CUSTOMER MANAGED KEY ──────────────────────────────
resource "aws_kms_key" "fintech_cmk" {
  description             = "FinTech CMK for S3, Secrets, and Logs encryption"
  deletion_window_in_days = 7
  enable_key_rotation     = true  # Auto-rotates every year

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "Enable IAM User Permissions"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "Allow S3 Service"
        Effect = "Allow"
        Principal = {
          Service = "s3.amazonaws.com"
        }
        Action = [
          "kms:GenerateDataKey",
          "kms:Decrypt"
        ]
        Resource = "*"
      },
      {
        Sid    = "Allow CloudTrail"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action = [
          "kms:GenerateDataKey",
          "kms:Decrypt"
        ]
        Resource = "*"
      },
      {
        Sid    = "Allow Lambda"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
        Action = [
          "kms:GenerateDataKey",
          "kms:Decrypt"
        ]
        Resource = "*"
      }
    ]
  })

  tags = {
    Project     = "FinTech-Capstone"
    Environment = "Production"
    Purpose     = "Data encryption CMK"
  }
}

# ── KMS KEY ALIAS ─────────────────────────────────────────
resource "aws_kms_alias" "fintech_cmk" {
  name          = "alias/fintech-cmk"
  target_key_id = aws_kms_key.fintech_cmk.key_id
}

# ── ENCRYPTED S3 BUCKET ───────────────────────────────────
resource "aws_s3_bucket" "encrypted" {
  bucket        = "fintech-encrypted-data-${data.aws_caller_identity.current.account_id}"
  force_destroy = true

  tags = {
    Project     = "FinTech-Capstone"
    Encryption  = "KMS-CMK"
  }
}

resource "aws_s3_bucket_public_access_block" "encrypted" {
  bucket                  = aws_s3_bucket.encrypted.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Apply KMS encryption to S3 bucket
resource "aws_s3_bucket_server_side_encryption_configuration" "encrypted" {
  bucket = aws_s3_bucket.encrypted.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.fintech_cmk.arn
    }
    bucket_key_enabled = true
  }
}

# ── UPLOAD TEST OBJECT to prove KMS encryption ────────────
resource "aws_s3_object" "test_encrypted" {
  bucket  = aws_s3_bucket.encrypted.id
  key     = "test-encrypted-file.txt"
  content = "This file is encrypted with KMS CMK - FinTech Capstone Evidence"

  tags = {
    Project    = "FinTech-Capstone"
    Encryption = "KMS-CMK"
  }
}

# ── SECRETS MANAGER (encrypted with KMS) ─────────────────
resource "aws_secretsmanager_secret" "app_secrets" {
  name                    = "fintech/app/secrets"
  description             = "Application secrets encrypted with KMS CMK"
  kms_key_id              = aws_kms_key.fintech_cmk.arn
  recovery_window_in_days = 0

  tags = {
    Project = "FinTech-Capstone"
  }
}

resource "aws_secretsmanager_secret_version" "app_secrets" {
  secret_id = aws_secretsmanager_secret.app_secrets.id
  secret_string = jsonencode({
    db_password = "SuperSecurePassword123!"
    api_key     = "fintech-api-key-encrypted"
    environment = "production"
  })
}

# ── ACM CERTIFICATE REQUEST ───────────────────────────────
# NOTE: ACM certificates require DNS validation with a real domain
# Commented out to avoid timeout errors during deployment
# To enable: Register a domain, update domain_name, and validate via DNS

# resource "aws_acm_certificate" "main" {
#   domain_name       = "fintech.nungari-projects.internal"
#   validation_method = "DNS"
#
#   tags = {
#     Project = "FinTech-Capstone"
#   }
#
#   lifecycle {
#     create_before_destroy = true
#   }
# }

# ── ALB HTTPS LISTENER ────────────────────────────────────
# Commented out - requires valid ACM certificate
# Uncomment after ACM certificate is validated

# resource "aws_lb_listener" "https" {
#   load_balancer_arn = "arn:aws:elasticloadbalancing:us-east-1:430287290736:loadbalancer/app/fintech-alb/09a14190f6b10730"
#   port              = 443
#   protocol          = "HTTPS"
#   ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
#   certificate_arn   = aws_acm_certificate.main.arn
#
#   default_action {
#     type = "fixed-response"
#     fixed_response {
#       content_type = "text/html"
#       message_body = "<h1>FinTech Secure Platform - HTTPS</h1>"
#       status_code  = "200"
#     }
#   }
#
#   tags = { Project = "FinTech-Capstone" }
# }

# ── HTTP to HTTPS REDIRECT ────────────────────────────────
# Commented out - requires HTTPS listener

# resource "aws_lb_listener_rule" "redirect_http" {
#   listener_arn = "arn:aws:elasticloadbalancing:us-east-1:430287290736:listener/app/fintech-alb/09a14190f6b10730/52a09c7f8ca9188d"
#   priority     = 100
#
#   action {
#     type = "redirect"
#     redirect {
#       port        = "443"
#       protocol    = "HTTPS"
#       status_code = "HTTP_301"
#     }
#   }
#
#   condition {
#     path_pattern {
#       values = ["/secure/*"]
#     }
#   }
# }

# ── OUTPUTS ───────────────────────────────────────────────
output "kms_key_id" {
  value = aws_kms_key.fintech_cmk.key_id
}

output "kms_key_arn" {
  value = aws_kms_key.fintech_cmk.arn
}

output "kms_alias" {
  value = aws_kms_alias.fintech_cmk.name
}

output "encrypted_bucket" {
  value = aws_s3_bucket.encrypted.bucket
}

output "secret_arn" {
  value = aws_secretsmanager_secret.app_secrets.arn
}

# ACM outputs commented out - uncomment when certificate is validated
# output "acm_certificate_arn" {
#   value = aws_acm_certificate.main.arn
# }
#
# output "acm_status" {
#   value = aws_acm_certificate.main.status
# }