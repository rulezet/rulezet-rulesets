rule WiltedTulip_Tools_back_RID2FE8 : APT DEMO EXE FILE T1003 {
   meta:
      description = "Detects Chrome password dumper used in Operation Wilted Tulip"
      author = "Florian Roth"
      reference = "http://www.clearskysec.com/tulip"
      date = "2017-07-23 12:17:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2022-12-21"
      hash1 = "b7faeaa6163e05ad33b310a8fdc696ccf1660c425fa2a962c3909eada5f2c265"
      tags = "APT, DEMO, EXE, FILE, T1003"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "%s.exe -f \"C:\\Users\\Admin\\Google\\Chrome\\TestProfile\" -o \"c:\\passlist.txt\"" fullword ascii
      $x2 = "\\ChromePasswordDump\\Release\\FireMaster.pdb" ascii
      $x3 = "//Dump Chrome Passwords to a Output file \"c:\\passlist.txt\"" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 2000KB and 1 of them )
}