rule ps1_toolkit_PowerUp_RID2EBB : DEMO FILE HKTL SCRIPT T1059_001 {
   meta:
      description = "Semiautomatically generated YARA rule - file PowerUp.ps1"
      author = "Florian Roth"
      reference = "https://github.com/vysec/ps1-toolkit"
      date = "2016-09-04 11:27:01"
      score = 80
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "fc65ec85dbcd49001e6037de9134086dd5559ac41ac4d1adf7cab319546758ad"
      tags = "DEMO, FILE, HKTL, SCRIPT, T1059_001"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "iex \"$Env:SystemRoot\\System32\\inetsrv\\appcmd.exe list vdir /text:vdir.name\" | % { " fullword ascii
      $s2 = "iex \"$Env:SystemRoot\\System32\\inetsrv\\appcmd.exe list apppools /text:name\" | % { " fullword ascii
      $s3 = "if ($Env:PROCESSOR_ARCHITECTURE -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBNAEQANgA0AA==')))) {" fullword ascii
      $s4 = "C:\\Windows\\System32\\InetSRV\\appcmd.exe list vdir /text:physicalpath | " fullword ascii
      $s5 = "if (Test-Path  (\"$Env:SystemRoot\\System32\\inetsrv\\appcmd.exe\"))" fullword ascii
      $s6 = "if (Test-Path  (\"$Env:SystemRoot\\System32\\InetSRV\\appcmd.exe\")) {" fullword ascii
      $s7 = "Write-Verbose \"Executing command '$Cmd'\"" fullword ascii
      $s8 = "Write-Warning \"[!] Target service" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0xbbef and filesize < 4000KB and 1 of them ) or ( 3 of them )
}