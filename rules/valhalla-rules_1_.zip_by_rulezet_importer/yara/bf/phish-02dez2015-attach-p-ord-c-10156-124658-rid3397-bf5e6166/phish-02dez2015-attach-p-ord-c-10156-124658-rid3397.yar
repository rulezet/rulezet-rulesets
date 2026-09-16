rule PHISH_02Dez2015_attach_P_ORD_C_10156_124658_RID3397 : DEMO FILE MAL T1203 T1566_001 {
   meta:
      description = "Phishing Wave - file P-ORD-C-10156-124658.xls"
      author = "Florian Roth"
      reference = "http://myonlinesecurity.co.uk/purchase-order-124658-gina-harrowell-clinimed-limited-word-doc-or-excel-xls-spreadsheet-malware/"
      date = "2015-12-02 14:54:21"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, FILE, MAL, T1203, T1566_001"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "Execute" ascii
      $s2 = "Process WriteParameterFiles" fullword ascii
      $s3 = "WScript.Shell" fullword ascii
      $s4 = "STOCKMASTER" fullword ascii
      $s5 = "InsertEmailFax" ascii
   condition: 
      uint16 ( 0 ) == 0xcfd0 and filesize < 200KB and all of them
}