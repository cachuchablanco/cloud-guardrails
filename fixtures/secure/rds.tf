resource "aws_db_subnet_group" "app" {
  name       = "secure-app-db"
  subnet_ids = [aws_subnet.private_a.id, aws_subnet.private_b.id]
  tags       = { Name = "secure-db-subnets" }
}

resource "aws_db_instance" "app" {
  identifier                  = "secure-app-db"
  engine                      = "postgres"
  engine_version              = "15.4"
  instance_class              = "db.t3.micro"
  allocated_storage           = 20
  username                    = "appadmin"
  manage_master_user_password = true
  db_subnet_group_name        = aws_db_subnet_group.app.name
  vpc_security_group_ids      = [aws_security_group.db.id]
  publicly_accessible         = false
  storage_encrypted           = true
  kms_key_id                  = aws_kms_key.data.arn
  skip_final_snapshot         = true
  backup_retention_period     = 7
  deletion_protection         = true

  tags = { Name = "secure-app-db" }
}
