rule KeeTheft_Out_Shellcode_RID2FAA : DEMO HKTL SCRIPT T1059_001 {
   meta:
      description = "Detects component of KeeTheft - KeePass dump tool - file Out-Shellcode.ps1"
      author = "Florian Roth"
      reference = "https://github.com/HarmJ0y/KeeThief"
      date = "2017-08-29 12:06:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "2afb1c8c82363a0ae43cad9d448dd20bb7d2762aa5ed3672cd8e14dee568e16b"
      tags = "DEMO, HKTL, SCRIPT, T1059_001"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "Write-Host \"Shellcode length: 0x$(($ShellcodeLength + 1).ToString('X4'))\"" fullword ascii
      $x2 = "$TextSectionInfo = @($MapContents | Where-Object { $_ -match '\\.text\\W+CODE' })[0]" fullword ascii
   condition: 
      ( filesize < 2KB and 1 of them )
}