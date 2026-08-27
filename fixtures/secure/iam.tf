resource "aws_iam_role" "app" {
  name = "secure-app-role"

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

resource "aws_iam_policy" "app_s3_read" {
  name        = "secure-app-s3-read"
  description = "Read objects in the private logs bucket only"

  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["s3:GetObject", "s3:ListBucket"],
      "Resource": [
        "arn:aws:s3:::acme-lab-private-logs",
        "arn:aws:s3:::acme-lab-private-logs/*"
      ]
    }
  ]
}
POLICY
}

resource "aws_iam_role_policy_attachment" "app_s3_read" {
  role       = aws_iam_role.app.name
  policy_arn = aws_iam_policy.app_s3_read.arn
}

resource "aws_iam_instance_profile" "app" {
  name = "secure-app-profile"
  role = aws_iam_role.app.name
}
