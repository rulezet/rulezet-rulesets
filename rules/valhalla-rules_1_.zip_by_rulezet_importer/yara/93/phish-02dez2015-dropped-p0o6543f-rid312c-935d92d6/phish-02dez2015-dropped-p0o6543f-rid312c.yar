rule PHISH_02Dez2015_dropped_p0o6543f_RID312C : DEMO EXE FILE MAL T1203 T1566_001 {
   meta:
      description = "Phishing Wave - file p0o6543f.exe"
      author = "Florian Roth"
      reference = "http://myonlinesecurity.co.uk/purchase-order-124658-gina-harrowell-clinimed-limited-word-doc-or-excel-xls-spreadsheet-malware/"
      date = "2015-12-02 13:11:11"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, EXE, FILE, MAL, T1203, T1566_001"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "netsh.exe" fullword wide
      $s2 = "routemon.exe" fullword wide
      $s3 = "script=" fullword wide
      $s4 = "disconnect" fullword wide
      $s5 = "GetClusterResourceTypeKey" fullword ascii
      $s6 = "QueryInformationJobObject" fullword ascii
      $s7 = "interface" fullword wide
      $s8 = "connect" fullword wide
      $s9 = "FreeConsole" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 250KB and all of them
}