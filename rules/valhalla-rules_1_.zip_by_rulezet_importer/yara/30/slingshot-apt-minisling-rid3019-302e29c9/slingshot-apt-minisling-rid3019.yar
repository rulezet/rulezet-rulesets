rule Slingshot_APT_Minisling_RID3019 : APT DEMO EXE FILE {
   meta:
      description = "Detects malware from Slingshot APT"
      author = "Florian Roth"
      reference = "https://securelist.com/apt-slingshot/84312/"
      date = "2018-03-09 12:25:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "{6D29520B-F138-442e-B29F-A4E7140F33DE}" fullword ascii wide
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 3000KB and 1 of them
}