# Planted CG-IAM-001: customer *:* policy plus AWS managed AdministratorAccess.
resource "aws_iam_role" "app" {
  name = "insecure-app-role"

  assume_role_policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": { "Service": "ec2.amazonaws.com" },
      "Action": "sts:AssumeRole"
    }
  ]
}
POLICY
}

resource "aws_iam_policy" "full_admin" {
  name        = "insecure-full-admin"
  description = "Planted wildcard admin"

  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "*",
      "Resource": "*"
    }
  ]
}
POLICY
}

resource "aws_iam_role_policy_attachment" "custom_admin" {
  role       = aws_iam_role.app.name
  policy_arn = aws_iam_policy.full_admin.arn
}

resource "aws_iam_role_policy_attachment" "managed_admin" {
  role       = aws_iam_role.app.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

resource "aws_iam_instance_profile" "app" {
  name = "insecure-app-profile"
  role = aws_iam_role.app.name
}
