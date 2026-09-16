rule DragonFly_APT_Sep17_4_RID2E5D : APT DEMO EXE FILE G0035 MAL {
   meta:
      description = "Detects malware from DrqgonFly APT report"
      author = "Florian Roth"
      reference = "https://www.symantec.com/connect/blogs/dragonfly-western-energy-sector-targeted-sophisticated-attack-group"
      date = "2017-09-12 11:11:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "2f159b71183a69928ba8f26b76772ec504aefeac71021b012bd006162e133731"
      tags = "APT, DEMO, EXE, FILE, G0035, MAL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "screen.exe" fullword wide
      $s2 = "PlatformInvokeUSER32" fullword ascii
      $s3 = "GetDesktopImageF" fullword ascii
      $s4 = "PlatformInvokeGDI32" fullword ascii
      $s5 = "GetDesktopImage" fullword ascii
      $s6 = "Too many arguments, going to store in current dir" fullword wide
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 60KB and all of them )
}