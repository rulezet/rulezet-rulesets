rule SUSP_RDP_File_Indicators_Oct24_1_RID326A : DEMO SUSP T1021_001 T1203 T1566_001 {
   meta:
      description = "Detects characteristics found in malicious RDP files used as email attachments in spear phishing campaigns"
      author = "Florian Roth"
      reference = "https://thecyberexpress.com/rogue-rdp-files-used-in-ukraine-cyberattacks/"
      date = "2024-10-25 14:04:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "280fbf353fdffefc5a0af40c706377142fff718c7b87bc8b0daab10849f388d0"
      hash2 = "8b45f5a173e8e18b0d5c544f9221d7a1759847c28e62a25210ad8265f07e96d5"
      hash3 = "9b8cb8b01ce4eafb9204250a3c28bfaf70cc76a99ce411ad52bbf1aa2b6cce34"
      tags = "DEMO, SUSP, T1021_001, T1203, T1566_001"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "redirectclipboard:i:1" wide fullword
      $s2 = "redirectprinters:i:1" wide fullword
      $s3 = "remoteapplicationmode:i:1" wide fullword
      $s4 = "username:s:" wide
      $s5 = "emoteapplicationicon:s:C:\\Windows\\SystemApps" wide
   condition: 
      filesize < 50KB and all of them
}