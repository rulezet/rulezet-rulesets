rule APT30_Generic_4_RID2C08 : APT DEMO FILE G0013 GEN {
   meta:
      description = "FireEye APT30 Report Sample"
      author = "Florian Roth"
      reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
      date = "2015-04-03 09:31:51"
      score = 85
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "b47e20ac5889700438dc241f28f4e224070810d2"
      hash2 = "a9a50673ac000a313f3ddba55d63d9773b9f4143"
      hash3 = "ac96d7f5957aef09bd983465c497de24c6d17a92"
      tags = "APT, DEMO, FILE, G0013, GEN"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "del NetEagle_Scout.bat" fullword
      $s1 = "NetEagle_Scout.bat" fullword
      $s2 = "\\visit.exe" 
      $s3 = "\\System.exe" 
      $s4 = "\\System.dat" 
      $s5 = "\\ieupdate.exe" 
      $s6 = "GOTO ERROR" fullword
      $s7 = ":ERROR" fullword
      $s9 = "IF EXIST " fullword
      $s10 = "ioiocn" fullword
      $s11 = "SetFileAttribute" fullword
      $s12 = "le_0*^il" fullword
      $s13 = "le_.*^il" fullword
      $s14 = "le_-*^il" fullword
   condition: 
      filesize < 250KB and uint16 ( 0 ) == 0x5A4D and all of them
}