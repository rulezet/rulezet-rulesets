rule Empire_Get_GPPPassword_RID2F8B : DEMO SCRIPT T1059 T1059_001 {
   meta:
      description = "Detects Empire component - file Get-GPPPassword.ps1"
      author = "Florian Roth"
      reference = "https://github.com/adaptivethreat/Empire"
      date = "2016-11-05 12:01:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "55a4519c4f243148a971e4860225532a7ce730b3045bde3928303983ebcc38b0"
      tags = "DEMO, SCRIPT, T1059, T1059_001"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "$Base64Decoded = [Convert]::FromBase64String($Cpassword)" fullword ascii
      $s2 = "$XMlFiles += Get-ChildItem -Path \"\\\\$DomainController\\SYSVOL\" -Recurse" ascii
      $s3 = "function Get-DecryptedCpassword {" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x7566 and filesize < 30KB and 1 of them ) or all of them
}