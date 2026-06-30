terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 4.0"
    }
  }
}

provider "aws" {
  access_key                  = "fake"
  secret_key                  = "fake"
  region                      = "us-east-1"
  skip_credentials_validation = true
  skip_metadata_api_check     = true
  skip_requesting_account_id  = true
  s3_use_path_style           = true

  endpoints {
    s3 = "http://s3.localhost.localstack.cloud:4566"
    ec2 = "http://localhost:4566"
  }
}

resource "aws_s3_bucket" "vulnerable_bucket" {
  bucket = "vulnerable-soc-bucket"
}

resource "aws_s3_bucket_acl" "vulnerable_bucket_acl" {
  bucket = aws_s3_bucket.vulnerable_bucket.id
  acl    = "public-read"
}
resource "aws_security_group" "open_sg" {
  name        = "wide-open-sg"
  description = "Intentionally vulnerable security group"

  ingress {
    description = "SSH open to the world"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}