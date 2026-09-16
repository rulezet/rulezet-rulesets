rule AllTheThings_RID2BB8 : DEMO EXE FILE HKTL {
   meta:
      description = "Detects AllTheThings_RID2BB8"
      author = "Florian Roth"
      reference = "https://github.com/subTee/AllTheThings_RID2BB8"
      date = "2017-07-27 09:18:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2022-12-21"
      hash1 = "5a0e9a9ce00d843ea95bd5333b6ab50cc5b1dbea648cc819cfe48482513ce842"
      tags = "DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "\\obj\\Debug\\AllTheThings_RID2BB8.pdb" ascii
      $x2 = "AllTheThings_RID2BB8.exe" fullword wide
      $x3 = "\\AllTheThings_RID2BB8.dll" ascii
      $x4 = "Hello From Main...I Don't Do Anything" fullword wide
      $x5 = "I am a basic COM Object" fullword wide
      $x6 = "I shouldn't really execute either." fullword wide
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 50KB and 1 of them )
}