# 1. ECR Repository
resource "aws_ecr_repository" "backend_repo" {
  name                 = var.ecr_repo_name
  image_tag_mutability = "MUTABLE"
  force_delete         = true

  image_scanning_configuration {
    scan_on_push = true
  }
}

# 2. IAM Role for App Runner
resource "aws_iam_role" "apprunner_role" {
  name = "AppRunnerECRAccessRole_TF"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "build.apprunner.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "apprunner_policy" {
  role       = aws_iam_role.apprunner_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSAppRunnerServicePolicyForECRAccess"
}

# 3. App Runner Service
resource "aws_apprunner_service" "backend_service" {
  service_name = var.service_name

  source_configuration {
    authentication_configuration {
      access_role_arn = aws_iam_role.apprunner_role.arn
    }

    image_repository {
      image_configuration {
        port = "8080"
      }
      image_identifier      = "${aws_ecr_repository.backend_repo.repository_url}:latest"
      image_repository_type = "ECR"
    }
  }

  depends_on = [aws_iam_role_policy_attachment.apprunner_policy]
}

output "ecr_repository_url" {
  value = aws_ecr_repository.backend_repo.repository_url
}

output "apprunner_service_url" {
  value = aws_apprunner_service.backend_service.service_url
}
