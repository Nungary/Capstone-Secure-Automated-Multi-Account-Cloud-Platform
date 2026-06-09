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
variable "vpc_id" {
  default = "vpc-03febdfc94ccb5668"
}

variable "subnet_ids" {
  default = [
    "subnet-085aeee91a51725a9",  # us-east-1a
    "subnet-0893c62241acd33eb"   # us-east-1b
  ]
}

# ── SECURITY GROUP for ALB ────────────────────────────────
resource "aws_security_group" "alb" {
  name        = "fintech-alb-sg"
  description = "Security group for ALB"
  vpc_id      = var.vpc_id

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Allow HTTP"
  }

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Allow HTTPS"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Project = "FinTech-Capstone" }
}

# ── SECURITY GROUP for EC2 ────────────────────────────────
resource "aws_security_group" "ec2" {
  name        = "fintech-ec2-sg"
  description = "Security group for EC2 web server"
  vpc_id      = var.vpc_id

  ingress {
    from_port       = 80
    to_port         = 80
    protocol        = "tcp"
    security_groups = [aws_security_group.alb.id]
    description     = "Allow HTTP from ALB only"
  }

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Allow SSH"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Project = "FinTech-Capstone" }
}

# ── EC2 INSTANCE (Web Server) ─────────────────────────────
resource "aws_instance" "web" {
  ami                    = "ami-0c02fb55956c7d316"
  instance_type          = "t2.micro"
  subnet_id              = var.subnet_ids[0]
  vpc_security_group_ids = [aws_security_group.ec2.id]

  user_data = <<-EOF
    #!/bin/bash
    yum update -y
    yum install -y httpd
    systemctl start httpd
    systemctl enable httpd
    echo "<html>
    <head><title>FinTech Secure Platform</title></head>
    <body>
    <h1>FinTech Capstone - Secure Web Application</h1>
    <p>Protected by AWS WAF, ALB, KMS, and ACM</p>
    <p>Account: ${data.aws_caller_identity.current.account_id}</p>
    <p>Region: us-east-1</p>
    </body>
    </html>" > /var/www/html/index.html
  EOF

  tags = {
    Name    = "fintech-web-server"
    Project = "FinTech-Capstone"
  }
}

# ── APPLICATION LOAD BALANCER ─────────────────────────────
resource "aws_lb" "main" {
  name               = "fintech-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb.id]
  subnets            = var.subnet_ids

  tags = { Project = "FinTech-Capstone" }
}

# ── TARGET GROUP ──────────────────────────────────────────
resource "aws_lb_target_group" "web" {
  name     = "fintech-web-tg"
  port     = 80
  protocol = "HTTP"
  vpc_id   = var.vpc_id

  health_check {
    path                = "/"
    healthy_threshold   = 2
    unhealthy_threshold = 3
    timeout             = 5
    interval            = 30
  }

  tags = { Project = "FinTech-Capstone" }
}

# ── REGISTER EC2 WITH TARGET GROUP ────────────────────────
resource "aws_lb_target_group_attachment" "web" {
  target_group_arn = aws_lb_target_group.web.arn
  target_id        = aws_instance.web.id
  port             = 80
}

# ── ALB LISTENER (HTTP) ───────────────────────────────────
resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.main.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.web.arn
  }

  tags = { Project = "FinTech-Capstone" }
}

# ── WAF WEB ACL ───────────────────────────────────────────
resource "aws_wafv2_web_acl" "main" {
  name        = "fintech-web-acl"
  description = "WAF for FinTech platform"
  scope       = "REGIONAL"

  default_action {
    allow {}
  }

  # Rule 1: AWS Managed Common Rule Set (blocks SQLi, XSS etc)
  rule {
    name     = "AWSManagedRulesCommonRuleSet"
    priority = 1

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesCommonRuleSet"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "CommonRuleSetMetric"
      sampled_requests_enabled   = true
    }
  }

  # Rule 2: Rate limiting — max 100 requests per 5 minutes per IP
  rule {
    name     = "RateLimitRule"
    priority = 2

    action {
      block {}
    }

    statement {
      rate_based_statement {
        limit              = 10
        aggregate_key_type = "IP"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "RateLimitMetric"
      sampled_requests_enabled   = true
    }
  }

  # Rule 3: Block SQL Injection explicitly
  rule {
    name     = "SQLiProtection"
    priority = 3

    action {
      block {}
    }

    statement {
      sqli_match_statement {
        field_to_match {
          query_string {}
        }
        text_transformation {
          priority = 1
          type     = "URL_DECODE"
        }
        text_transformation {
          priority = 2
          type     = "HTML_ENTITY_DECODE"
        }
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "SQLiProtectionMetric"
      sampled_requests_enabled   = true
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "FintechWAFMetric"
    sampled_requests_enabled   = true
  }

  tags = { Project = "FinTech-Capstone" }
}

# ── ATTACH WAF TO ALB ─────────────────────────────────────
resource "aws_wafv2_web_acl_association" "main" {
  resource_arn = aws_lb.main.arn
  web_acl_arn  = aws_wafv2_web_acl.main.arn
}

# ── WAF LOGGING to CloudWatch ─────────────────────────────
resource "aws_cloudwatch_log_group" "waf" {
  name              = "aws-waf-logs-fintech"
  retention_in_days = 7
  tags              = { Project = "FinTech-Capstone" }
}

resource "aws_wafv2_web_acl_logging_configuration" "main" {
  log_destination_configs = [aws_cloudwatch_log_group.waf.arn]
  resource_arn            = aws_wafv2_web_acl.main.arn
}

# ── OUTPUTS ───────────────────────────────────────────────
output "alb_dns_name" {
  value       = aws_lb.main.dns_name
  description = "Use this to test your web app"
}

output "web_acl_id" {
  value = aws_wafv2_web_acl.main.id
}

output "ec2_instance_id" {
  value = aws_instance.web.id
}