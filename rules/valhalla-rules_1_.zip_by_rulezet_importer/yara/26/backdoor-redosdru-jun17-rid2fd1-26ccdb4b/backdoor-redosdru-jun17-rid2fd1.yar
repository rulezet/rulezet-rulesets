rule Backdoor_Redosdru_Jun17_RID2FD1 : DEMO EXE FILE HIGHVOL MAL {
   meta:
      description = "Detects malware Redosdru - file systemHome.exe"
      author = "Florian Roth"
      reference = "https://www.trellix.com/blogs/research/"
      date = "2017-06-04 12:13:21"
      score = 90
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2024-07-19"
      hash1 = "4f49e17b457ef202ab0be905691ef2b2d2b0a086a7caddd1e70dd45e5ed3b309"
      tags = "DEMO, EXE, FILE, HIGHVOL, MAL"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "%s\\%d.gho" fullword ascii
      $x2 = "%s\\nt%s.dll" fullword ascii
      $x3 = "baijinUPdate" fullword ascii
      $s1 = "RegQueryValueEx(Svchost\\netsvcs)" fullword ascii
      $s2 = "serviceone" fullword ascii
      $s3 = "\x1f#p \x1f#p \x1f#p \x1f#p \x1f#p \x1f#p \x1f#p \x1f#p \x1f#p \x1f#p \x1f#p \x1f#p \x1f#p \x1f#p \x1f#p \x1f#p \x1f#p \x1f#p \x1f#p \x1f#p \x1f#p \x1f#p \x1f#p \x1f#p \x1f#f \x1f#" fullword ascii
      $s4 = "servicetwo" fullword ascii
      $s5 = "UpdateCrc" fullword ascii
      $s6 = "\x1f#[ \x1f#x \x1f#x \x1f#x \x1f#x \x1f#x \x1f#x \x1f#x \x1f#x \x1f#x \x1f#x \x1f#x \x1f#x \x1f#x \x1f#x \x1f#x \x1f#x \x1f#x \x1f#x \x1f#x \x1f#x \x1f#" fullword ascii
      $s7 = "nwsaPAgEnT" fullword ascii
      $s8 = "%-24s %-15s 0x%x(%d) " fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 700KB and 1 of ( $x* ) or 4 of them )
}