rule Powershell_Netcat {
   meta:
      description = "Detects a Powershell version of the Netcat network hacking tool"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      score = 60
      date = "10.10.2014"
      id = "e4b018c0-3214-5102-93b1-6a048324f9dd"
   strings:
      $s0 = "[ValidateRange(1, 65535)]" fullword
      $s1 = "$Client = New-Object -TypeName System.Net.Sockets.TcpClient" fullword
      $s2 = "$Buffer = New-Object -TypeName System.Byte[] -ArgumentList $Client.ReceiveBufferSize" fullword
   condition:
      all of them
}