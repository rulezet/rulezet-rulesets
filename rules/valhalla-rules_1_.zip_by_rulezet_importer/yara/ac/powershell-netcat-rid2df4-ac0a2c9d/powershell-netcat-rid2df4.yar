rule Powershell_Netcat_RID2DF4 : DEMO SCRIPT T1059 T1059_001 {
   meta:
      description = "Detects a Powershell version of the Netcat network hacking tool"
      author = "Florian Roth"
      reference = "-"
      date = "2014-10-10 10:53:51"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1059, T1059_001"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "[ValidateRange(1, 65535)]" fullword
      $s1 = "$Client = New-Object -TypeName System.Net.Sockets.TcpClient" fullword
      $s2 = "$Buffer = New-Object -TypeName System.Byte[] -ArgumentList $Client.ReceiveBufferSize" fullword
   condition: 
      all of them
}