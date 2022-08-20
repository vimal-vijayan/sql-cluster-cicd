resource "aws_security_group" "allow_tls" {
  name        = "allow_tls_${var.cluster_name}"
  description = "Allow TLS inbound traffic"
  vpc_id      = var.vpc_id

  ingress {
    description = "RDP from VPC"
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = [var.sg_cidr]
  }

  egress {
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }

  ingress {
    from_port   = 5985
    protocol    = "tcp"
    to_port     = 5985
    cidr_blocks = [var.sg_cidr]
    description = "Winrm-Http"
  }

  ingress {
    from_port   = 1433
    protocol    = "tcp"
    to_port     = 1433
    cidr_blocks = [var.sg_cidr]
    description = "MSSQL"
  }

  ingress {
    from_port   = 0
    protocol    = "-1"
    to_port     = 0
    cidr_blocks = [var.sg_cidr]
    description = "All Traffic for Cluster Creation"
  }

  ingress {
    from_port   = 0
    protocol    = "-1"
    to_port     = 0
    cidr_blocks = [var.vpc_cidr]
    description = "All Traffic for Cluster Creation"
  }

  ingress {
    from_port   = 0
    protocol    = "tcp"
    to_port     = 65535
    cidr_blocks = [var.vpc_cidr]
    description = "Cross Region VPC"
  }

  ingress {
    from_port   = 1433
    protocol    = "tcp"
    to_port     = 1433
    cidr_blocks = [data.aws_vpc.selector.cidr_block]
    description = "VPC-VPC MSSQL Traffic"
  }

  tags = {
    Name = "allow_tls_${var.cluster_name}"
  }
}

resource "aws_ebs_volume" "xvdh" {
  count             = length(var.vm_names)
  availability_zone = data.aws_subnet.subnet[count.index % length(var.subnet_id)].availability_zone
  size              = var.hDriveSize
  type              = "gp3"

  tags = {
    Name = "xvdh"
  }
}

resource "aws_ebs_volume" "xvdf" {
  count             = length(var.vm_names)
  availability_zone = data.aws_subnet.subnet[count.index % length(var.subnet_id)].availability_zone
  size              = var.fDriveSize
  type              = "gp3"

  tags = {
    Name = "xvdf"
  }
}

resource "aws_ebs_volume" "xvdg" {
  count             = length(var.vm_names)
  availability_zone = data.aws_subnet.subnet[count.index % length(var.subnet_id)].availability_zone
  size              = var.gDriveSize
  type              = "gp3"

  tags = {
    Name = "xvdg"
  }
}

resource "aws_network_interface" "secondary_eni" {
  count             = length(var.vm_names)
  private_ips_count = 1
  //  subnet_id         = var.subnet_id[count.index] == "" ? var.subnet_id[count.index - count.index] : var.subnet_id[count.index]
  //  subnet_id         = var.subnet_id[count.index] == "" ? var.subnet_id[count.index - count.index] : var.subnet_id[(0)]
  subnet_id         = tolist(var.subnet_id)[count.index % length(var.subnet_id)]
  security_groups   = [aws_security_group.allow_tls.id]
}

resource "aws_instance" "sqlNode" {
  count         = length(var.vm_names)
  ami           = data.aws_ami.windows.id
  instance_type = var.instance_type
  key_name      = "sql-test-sr-key"

  //  iam_instance_profile = "DCSSSMAccessRole"
  //  user_data = "${file("../../../packman.ps1 -ComputerName "${var.vm_names[count.index]}" -xvdfVolumeId "${aws_ebs_volume.xvdf[count.index].id}" -xvdfSize "${var.fDriveSize - 10}" -xvdhVolumeId "${aws_ebs_volume.xvdh[count.index].id}" -xvdhSize "${var.hDriveSize - 10 }" -xvdgVolumeId "${aws_ebs_volume.xvdg[count.index].id}" -xvdgSize "${var.gDriveSize - 10}"")}"
  user_data = <<EOF
          <powershell>
          $op = Get-LocalUSer | where-Object Name -eq "tempUser" | Measure
          if ($op.Count -eq 0) {
              $Password = ConvertTo-SecureString "temp@1234@*" -AsPlainText -Force
              New-LocalUser "tempUser" -Password $Password -FullName "tempUser" -Description "Temporary account"
              Add-LocalGroupMember -Group "Administrators" -Member "tempUser"
              Add-LocalGroupMember -Group "Remote Desktop Users" -Member "tempUser"
          }

          #Instal SSM
          write-output "Entering UD script"
          C:\ProgramData\Amazon\EC2-Windows\Launch\Scripts\InitializeInstance.ps1 -Schedule
          write-output "Exiting out"
          Invoke-WebRequest https://s3.amazonaws.com/ec2-downloads-windows/SSMAgent/latest/windows_amd64/AmazonSSMAgentSetup.exe -OutFile C:\SSMAgent_latest.exe
          Start-Process -FilePath C:\SSMAgent_latest.exe -ArgumentList "/S" -Passthru -Wait -NoNewWindow
          sleep 60

          $volumeLogPath = "c:\windows\temp\volumes.log"
          New-Item $volumeLogPath

          $volumeId = "${aws_ebs_volume.xvdf[count.index].id}".replace('-','')
          Add-Content $volumeLogPath "volumeId1=$volumeId"
          $volumeId = "${aws_ebs_volume.xvdh[count.index].id}".replace('-','')
          Add-Content $volumeLogPath "volumeId2=$volumeId"
          $volumeId = "${aws_ebs_volume.xvdg[count.index].id}".replace('-','')
          Add-Content $volumeLogPath "volumeId3=$volumeId"

          Rename-Computer -NewName "${var.vm_names[count.index]}" #-Restart -Force

          $ErrorActionPreference="Stop";If(-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent() ).IsInRole( [Security.Principal.WindowsBuiltInRole] "Administrator")){ throw "Run command in an administrator PowerShell prompt"};If($PSVersionTable.PSVersion -lt (New-Object System.Version("3.0"))){ throw "The minimum version of Windows PowerShell that is required by the script (3.0) does not match the currently running version of Windows PowerShell." };If(-NOT (Test-Path $env:SystemDrive\'azagent')){mkdir $env:SystemDrive\'azagent'}; cd $env:SystemDrive\'azagent'; for($i=1; $i -lt 100; $i++){$destFolder="A"+$i.ToString();if(-NOT (Test-Path ($destFolder))){mkdir $destFolder;cd $destFolder;break;}}; $agentZip="$PWD\agent.zip";$DefaultProxy=[System.Net.WebRequest]::DefaultWebProxy;$securityProtocol=@();$securityProtocol+=[Net.ServicePointManager]::SecurityProtocol;$securityProtocol+=[Net.SecurityProtocolType]::Tls12;[Net.ServicePointManager]::SecurityProtocol=$securityProtocol;$WebClient=New-Object Net.WebClient; $Uri='https://vstsagentpackage.azureedge.net/agent/2.206.1/vsts-agent-win-x64-2.206.1.zip';if($DefaultProxy -and (-not $DefaultProxy.IsBypassed($Uri))){$WebClient.Proxy= New-Object Net.WebProxy($DefaultProxy.GetProxy($Uri).OriginalString, $True);}; $WebClient.DownloadFile($Uri, $agentZip);Add-Type -AssemblyName System.IO.Compression.FileSystem;[System.IO.Compression.ZipFile]::ExtractToDirectory( $agentZip, "$PWD");.\config.cmd --environment --unattended --environmentname “test” --agent $env:COMPUTERNAME --runasservice --work '_work' --url 'https://dev.azure.com/dev-apps-its-us-deloitte/' --projectname ‘DCMigration-Sandbox’ --auth PAT --token ${var.ado_token}; Remove-Item $agentZip;

          Restart-Computer -Force
          </powershell>
  EOF

  timeouts {
    create = "60m"
  }
  root_block_device {
    volume_size = 90
    volume_type = "gp3"
  }

  network_interface {
    device_index         = 0
    network_interface_id = length(var.vm_names) == 1 ? aws_network_interface.secondary_eni[(0)].id : aws_network_interface.secondary_eni[count.index].id
  }

  tags = {
    Name = var.vm_names[count.index]
  }
}


data "aws_network_interface" "eni_data" {
  count = length(var.vm_names)
  id    = aws_network_interface.secondary_eni[count.index].id
}

resource "aws_volume_attachment" "ebs_att1" {
  count       = length(var.vm_names)
  device_name = "xvdh"
  volume_id   = aws_ebs_volume.xvdh[count.index].id
  instance_id = aws_instance.sqlNode[count.index].id
}

resource "aws_volume_attachment" "ebs_att2" {
  count       = length(var.vm_names)
  device_name = "xvdf"
  volume_id   = aws_ebs_volume.xvdf[count.index].id
  instance_id = aws_instance.sqlNode[count.index].id
}

resource "aws_volume_attachment" "ebs_att3" {
  count       = length(var.vm_names)
  device_name = "xvdg"
  volume_id   = aws_ebs_volume.xvdg[count.index].id
  instance_id = aws_instance.sqlNode[count.index].id
}

