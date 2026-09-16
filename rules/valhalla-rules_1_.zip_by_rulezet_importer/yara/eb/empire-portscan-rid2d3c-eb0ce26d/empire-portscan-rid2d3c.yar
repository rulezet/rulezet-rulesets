rule Empire_portscan_RID2D3C : DEMO SCRIPT SUSP T1059_001 {
   meta:
      description = "Empire - a pure PowerShell post-exploitation agent - file portscan.py"
      author = "Florian Roth"
      reference = "https://github.com/PowerShellEmpire/Empire"
      date = "2015-08-06 10:23:11"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, SUSP, T1059_001"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "script += \"Invoke-PortScan -noProgressMeter -f\"" fullword ascii
      $s2 = "script += \" | ? {$_.alive}| Select-Object HostName,@{name='OpenPorts';expression={$_.openPorts -join ','}} | ft -wrap | Out-Str" ascii
   condition: 
      filesize < 14KB and all of them
}