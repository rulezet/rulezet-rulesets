rule SUSP_RAR_NtdsDIT_RID2C79 : DEMO FILE SUSP {
   meta:
      description = "Detects suspicious RAR file that contains ntds.dit or SAM export"
      author = "Florian Roth"
      reference = "https://www.cybereason.com/blog/operation-soft-cell-a-worldwide-campaign-against-telecommunications-providers"
      date = "2019-12-16 09:50:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, FILE, SUSP"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "ntds.dit0" ascii fullword
      $x2 = { 0? 53 41 4D 30 01 00 03 } 
      $x3 = { 0? 73 61 6D 30 01 00 03 } 
   condition: 
      uint32 ( 0 ) == 0x21726152 and 1 of them
}