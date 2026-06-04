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

# ── PERMISSION BOUNDARY ────────────────────────────────────
# This is a HARD CEILING — even if a role has full access,
# it CANNOT perform these destructive S3 actions
resource "aws_iam_policy" "devops_boundary" {
  name        = "DevOpsBoundary"
  description = "Permission boundary - blocks destructive S3 actions"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowGeneralDevOps"
        Effect = "Allow"
        Action = [
          "ec2:*",
          "s3:GetObject",
          "s3:PutObject",
          "s3:ListBucket",
          "cloudtrail:DescribeTrails",
          "cloudtrail:GetTrailStatus",
          "logs:*",
          "cloudwatch:*",
          "iam:GetRole",
          "iam:ListRoles",
          "sts:AssumeRole"
        ]
        Resource = "*"
      },
      {
        Sid    = "DenyDestructiveS3"
        Effect = "Deny"
        Action = [
          "s3:DeleteBucket",
          "s3:DeleteObject",
          "s3:PutBucketPolicy",
          "s3:DeleteBucketPolicy"
        ]
        Resource = "*"
      }
    ]
  })
}

# ── DEVOPS ENGINEER ROLE ───────────────────────────────────
# This role is used by GitHub Actions via OIDC
# It inherits the boundary above — cannot exceed it
resource "aws_iam_role" "devops_engineer" {
  name                 = "DevOpsEngineerRole"
  permissions_boundary = aws_iam_policy.devops_boundary.arn

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowGitHubOIDC"
        Effect = "Allow"
        Principal = {
          Federated = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:oidc-provider/token.actions.githubusercontent.com"
        }
        Action = "sts:AssumeRoleWithWebIdentity"
        Condition = {
          StringEquals = {
            "token.actions.githubusercontent.com:aud" = "sts.amazonaws.com"
          }
          StringLike = {
            "token.actions.githubusercontent.com:sub" = "repo:Nungary/Capstone-Secure-Automated-Multi-Account-Cloud-Platform:ref:refs/heads/main"
          }
        }
      }
    ]
  })

  tags = {
    Project     = "FinTech-Capstone"
    Environment = "Production"
  }
}

# ── ATTACH POLICY TO ROLE ──────────────────────────────────
resource "aws_iam_role_policy_attachment" "devops_engineer" {
  role       = aws_iam_role.devops_engineer.name
  policy_arn = aws_iam_policy.devops_boundary.arn
}

# ── OIDC PROVIDER ──────────────────────────────────────────
# This tells AWS to trust GitHub Actions tokens
resource "aws_iam_openid_connect_provider" "github" {
  url = "https://token.actions.githubusercontent.com"

  client_id_list = [
    "sts.amazonaws.com"
  ]

  # GitHub's OIDC thumbprint
  thumbprint_list = [
    "6938fd4d98bab03faadb97b34396831e3780aea1",
    "1c58a3a8518e8759bf075b76b750d4f2df264fcd"
  ]

  tags = {
    Project = "FinTech-Capstone"
  }
}

# ── OUTPUTS ────────────────────────────────────────────────
output "devops_role_arn" {
  value       = aws_iam_role.devops_engineer.arn
  description = "Use this ARN in your GitHub Actions workflow"
}

output "boundary_policy_arn" {
  value = aws_iam_policy.devops_boundary.arn
}

output "oidc_provider_arn" {
  value = aws_iam_openid_connect_provider.github.arn
}