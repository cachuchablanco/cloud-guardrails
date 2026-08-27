resource "aws_security_group" "app" {
  name        = "secure-app"
  description = "App SG: SSH from RFC1918 only"
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "SSH from private VPC CIDR"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["10.20.0.0/16"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "secure-app-sg" }
}

resource "aws_security_group" "db" {
  name        = "secure-db"
  description = "DB SG: postgres from app SG only"
  vpc_id      = aws_vpc.main.id

  ingress {
    description     = "Postgres from app"
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.app.id]
  }

  tags = { Name = "secure-db-sg" }
}
