rule MAL_Emdivi_Gen3_RID2C54 : DEMO EXE FILE MAL emdivi {
   meta:
      description = "Detects Emdivi Malware"
      author = "Florian Roth"
      reference = "https://securelist.com/blog/research/71876/new-activity-of-the-blue-termite-apt/"
      date = "2015-08-20 09:44:31"
      score = 80
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2023-01-06"
      hash1 = "008f4f14cf64dc9d323b6cb5942da4a99979c4c7d750ec1228d8c8285883771e"
      hash2 = "a94bf485cebeda8e4b74bbe2c0a0567903a13c36b9bf60fab484a9b55207fe0d"
      tags = "DEMO, EXE, FILE, MAL, emdivi"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; SV1; .NET CLR 2.0.50727.42)" fullword ascii
      $s2 = "\\Mozilla\\Firefox\\Profiles\\" ascii
      $s4 = "\\auto.cfg" ascii
      $s5 = "/ncsi.txt" fullword ascii
      $s6 = "/en-us/default.aspx" fullword ascii
      $s7 = "cmd /c" fullword ascii
      $s9 = "APPDATA" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 850KB and ( ( $x1 and 1 of ( $s* ) ) or ( 4 of ( $s* ) ) )
}