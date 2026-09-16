rule SUSP_Email_Suspicious_OneNote_Attachment_Jan23_2_RID3926 : DEMO SUSP T1203 T1566_001 {
   meta:
      description = "Detects suspicious OneNote attachment that has a file name often used in phishing attacks"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2023-01-27 18:51:31"
      score = 65
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SUSP, T1203, T1566_001"
      minimum_yara = "3.5.0"
      
   strings:
      $hc1 = { 2E 6F 6E 65 22 0D 0A 0D 0A 35 46 4A 63 65 } 
      $x01 = " attachment; filename=\"Invoice" nocase
      $x02 = " attachment; filename=\"ORDER" nocase
      $x03 = " attachment; filename=\"PURCHASE" nocase
      $x04 = " attachment; filename=\"SHIP" nocase
   condition: 
      filesize < 5MB and $hc1 and 1 of ( $x* )
}