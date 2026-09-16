rule WiltedTulip_tdtess_RID2E7E : APT DEMO EXE FILE T1569_002 {
   meta:
      description = "Detects malicious service used in Operation Wilted Tulip"
      author = "Florian Roth"
      reference = "http://www.clearskysec.com/tulip"
      date = "2017-07-23 11:16:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "3fd28b9d1f26bd0cee16a167184c9f4a22fd829454fd89349f2962548f70dc34"
      tags = "APT, DEMO, EXE, FILE, T1569_002"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "d2lubG9naW4k" fullword wide
      $x2 = "C:\\Users\\admin\\Documents\\visual studio 2015\\Projects\\Export\\TDTESS_ShortOne\\WinService Template\\" ascii
      $s1 = "\\WinService Template\\obj\\x64\\x64\\winlogin" ascii
      $s2 = "winlogin.exe" fullword wide
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 200KB and ( 1 of ( $x* ) or 2 of them ) )
}