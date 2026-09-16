rule Invoke_SMBExec_Invoke_WMIExec_1_RID326F : DEMO SCRIPT T1059 T1059_001 {
   meta:
      description = "Semiautomatically generated YARA rule - from files Invoke-SMBExec.ps1, Invoke-WMIExec.ps1"
      author = "Florian Roth"
      reference = "https://github.com/Kevin-Robertson/Invoke-TheHash"
      date = "2017-06-14 14:05:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "674fc045dc198874f323ebdfb9e9ff2f591076fa6fac8d1048b5b8d9527c64cd"
      hash2 = "b41bd54bbf119d153e0878696cd5a944cbd4316c781dd8e390507b2ec2d949e7"
      tags = "DEMO, SCRIPT, T1059, T1059_001"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "$process_ID = $process_ID -replace \"-00-00\",\"\"" fullword ascii
      $s2 = "Write-Output \"$Target did not respond\"" fullword ascii
      $s3 = "[Byte[]]$packet_call_ID_bytes = [System.BitConverter]::GetBytes($packet_call_ID)" fullword ascii
   condition: 
      all of them
}