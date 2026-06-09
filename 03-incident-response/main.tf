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

# ── VARIABLES ─────────────────────────────────────────────
variable "sns_topic_arn" {
  description = "SNS topic ARN for security alerts"
  default     = "arn:aws:sns:us-east-1:430287290736:fintech-security-alerts"
}

variable "guardduty_detector_id" {
  description = "GuardDuty detector ID"
  default     = "fccf48f4bce7dd12b58f6efe41fa622a"
}

# ── S3 BUCKET for findings ────────────────────────────────
resource "aws_s3_bucket" "findings" {
  bucket        = "fintech-security-findings-${data.aws_caller_identity.current.account_id}"
  force_destroy = true
  tags = {
    Project = "FinTech-Capstone"
  }
}

resource "aws_s3_bucket_public_access_block" "findings" {
  bucket                  = aws_s3_bucket.findings.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# ── IAM ROLE for Lambda ───────────────────────────────────
resource "aws_iam_role" "lambda_incident" {
  name = "LambdaIncidentResponder"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "lambda_incident" {
  name = "LambdaIncidentPolicy"
  role = aws_iam_role.lambda_incident.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "arn:aws:logs:*:*:*"
      },
      {
        Effect   = "Allow"
        Action   = ["s3:PutObject", "s3:GetObject"]
        Resource = "${aws_s3_bucket.findings.arn}/*"
      },
      {
        Effect   = "Allow"
        Action   = ["sns:Publish"]
        Resource = var.sns_topic_arn
      },
      {
        Effect = "Allow"
        Action = [
          "ec2:CreateTags",
          "ec2:DescribeInstances",
          "ec2:ModifyInstanceAttribute"
        ]
        Resource = "*"
      }
    ]
  })
}

# ── LAMBDA FUNCTION ───────────────────────────────────────
data "archive_file" "lambda_zip" {
  type        = "zip"
  source_file = "${path.module}/lambda_function.py"
  output_path = "${path.module}/lambda_function.zip"
}

resource "aws_lambda_function" "incident_responder" {
  filename         = data.archive_file.lambda_zip.output_path
  function_name    = "IncidentResponder"
  role             = aws_iam_role.lambda_incident.arn
  handler          = "lambda_function.lambda_handler"
  runtime          = "python3.12"
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256
  timeout          = 60

  environment {
    variables = {
      SNS_TOPIC_ARN = var.sns_topic_arn
      S3_BUCKET     = aws_s3_bucket.findings.bucket
    }
  }

  tags = {
    Project = "FinTech-Capstone"
  }
}

# ── IAM ROLE for Step Functions ───────────────────────────
resource "aws_iam_role" "step_functions" {
  name = "StepFunctionsIncidentRole"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "states.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "step_functions" {
  name = "StepFunctionsPolicy"
  role = aws_iam_role.step_functions.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["lambda:InvokeFunction"]
      Resource = aws_lambda_function.incident_responder.arn
    }]
  })
}

# ── STEP FUNCTIONS STATE MACHINE ──────────────────────────
resource "aws_sfn_state_machine" "incident_response" {
  name     = "IncidentResponseWorkflow"
  role_arn = aws_iam_role.step_functions.arn

  definition = jsonencode({
    Comment = "Automated incident response workflow"
    StartAt = "ValidateFinding"
    States = {
      ValidateFinding = {
        Type    = "Task"
        Resource = aws_lambda_function.incident_responder.arn
        Next    = "CheckSeverity"
        Catch = [{
          ErrorEquals = ["States.ALL"]
          Next        = "HandleError"
        }]
      }
      CheckSeverity = {
        Type = "Choice"
        Choices = [{
          Variable      = "$.severity"
          NumericGreaterThanEquals = 7
          Next          = "HighSeverityResponse"
        }]
        Default = "LowSeverityLog"
      }
      HighSeverityResponse = {
        Type    = "Task"
        Resource = aws_lambda_function.incident_responder.arn
        End     = true
      }
      LowSeverityLog = {
        Type   = "Pass"
        Result = "Low severity - logged only"
        End    = true
      }
      HandleError = {
        Type   = "Pass"
        Result = "Error handled"
        End    = true
      }
    }
  })

  tags = {
    Project = "FinTech-Capstone"
  }
}

# ── IAM ROLE for EventBridge ──────────────────────────────
resource "aws_iam_role" "eventbridge" {
  name = "EventBridgeIncidentRole"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "eventbridge" {
  name = "EventBridgePolicy"
  role = aws_iam_role.eventbridge.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["states:StartExecution"]
      Resource = aws_sfn_state_machine.incident_response.arn
    }]
  })
}

# ── EVENTBRIDGE RULE ──────────────────────────────────────
# Triggers on HIGH severity GuardDuty findings
resource "aws_cloudwatch_event_rule" "guardduty_high" {
  name        = "GuardDutyHighSeverity"
  description = "Triggers on GuardDuty findings severity 7+"

  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail-type = ["GuardDuty Finding"]
    detail = {
      severity = [{
        numeric = [">=", 7]
      }]
    }
  })
}

resource "aws_cloudwatch_event_target" "step_functions" {
  rule     = aws_cloudwatch_event_rule.guardduty_high.name
  arn      = aws_sfn_state_machine.incident_response.arn
  role_arn = aws_iam_role.eventbridge.arn
}

# ── OUTPUTS ───────────────────────────────────────────────
output "lambda_function_name" {
  value = aws_lambda_function.incident_responder.function_name
}

output "step_functions_arn" {
  value = aws_sfn_state_machine.incident_response.arn
}

output "findings_bucket" {
  value = aws_s3_bucket.findings.bucket
}

output "eventbridge_rule" {
  value = aws_cloudwatch_event_rule.guardduty_high.name
}