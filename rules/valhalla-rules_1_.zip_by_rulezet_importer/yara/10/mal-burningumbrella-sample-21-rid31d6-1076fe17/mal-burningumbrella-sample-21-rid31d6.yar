rule MAL_BurningUmbrella_Sample_21_RID31D6 : APT DEMO EXE FILE MAL {
   meta:
      description = "Detects malware sample from Burning Umbrella report"
      author = "Florian Roth"
      reference = "https://401trg.pw/burning-umbrella/"
      date = "2018-05-04 13:39:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "4b7b9c2a9d5080ccc4e9934f2fd14b9d4e8f6f500889bf9750f1d672c8724438"
      tags = "APT, DEMO, EXE, FILE, MAL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "c:\\windows\\ime\\setup.exe" fullword ascii
      $s2 = "ws.run \"later.bat /start\",0Cet " fullword ascii
      $s3 = "del later.bat" fullword ascii
      $s4 = "mycrs.xls" fullword ascii
      $a1 = "-el -s2 \"-d%s\" \"-p%s\" \"-sp%s\"" fullword ascii
      $a2 = "<set ws=wscript.createobject(\"wscript.shell\")" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 500KB and 2 of them
}