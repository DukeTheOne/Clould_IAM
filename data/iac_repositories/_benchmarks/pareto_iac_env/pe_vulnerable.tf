# Vulnerable Privilege Escalation Pattern: iam:PassRole with Lambda
resource "aws_iam_user" "intern_dev" {
  name = "intern-dev"
}

resource "aws_iam_role" "privileged_lambda_exec_role" {
  name = "lambda-superadmin-exec"
  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "lambda.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF
}

resource "aws_iam_policy" "admin_access_policy" {
  name = "CrownJewelVaultAccess"
  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:PutObject"
      ],
      "Resource": "arn:aws:s3:::confidential-crown-jewels/*"
    }
  ]
}
EOF
}

resource "aws_iam_role_policy_attachment" "lambda_admin_attach" {
  role       = aws_iam_role.privileged_lambda_exec_role.name
  policy_arn = aws_iam_policy.admin_access_policy.arn
}

# Intern policy granting PassRole and Lambda creation
resource "aws_iam_user_policy" "intern_escalator_policy" {
  name = "LambdaDeployPermission"
  user = aws_iam_user.intern_dev.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["iam:PassRole"]
        Resource = [aws_iam_role.privileged_lambda_exec_role.arn]
      },
      {
        Effect   = "Allow"
        Action   = ["lambda:CreateFunction", "lambda:InvokeFunction"]
        Resource = ["*"]
      }
    ]
  })
}
