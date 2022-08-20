##To create a network load balancer

resource "aws_lb" "nlb_lb" {
  name                             = "sql-loadbalancer"
  internal                         = true
  load_balancer_type               = "network"
  //  subnets = data.aws_subnet.subnet.vpc_id
  subnets                          = var.subnet_id
  enable_cross_zone_load_balancing = true
  ip_address_type                  = "ipv4"
  depends_on                       = [
    aws_instance.sqlNode
  ]
}

##Network Load balancer listener creation
resource "aws_lb_listener" "nlb_lb" {

  load_balancer_arn = aws_lb.nlb_lb.arn
  protocol          = "TCP"
  port              = "1433"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.nlb_lb.arn
  }
}

##Network load balancer Target Group

resource "aws_lb_target_group" "nlb_lb" {
  name        = "test-tg"
  port        = "1433"
  target_type = "instance"
  protocol    = "TCP"
  vpc_id      = var.vpc_id
  health_check {
    protocol            = "TCP"
    port                = "31000"
    healthy_threshold   = "5"
    unhealthy_threshold = "5"
    //    timeout = "5"
    interval            = "30"
  }
  depends_on = [
    aws_lb.nlb_lb
  ]

  lifecycle {
    create_before_destroy = true
  }
}
##To register instance to target group
resource "aws_lb_target_group_attachment" "nlb_lb" {
  target_group_arn = aws_lb_target_group.nlb_lb.arn
  count            = length(var.vm_names)
  target_id        = aws_instance.sqlNode[count.index].id
  port             = 1433
}