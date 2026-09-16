rule APT30_Generic_J_RID2C1E : APT DEMO FILE G0013 GEN {
   meta:
      description = "FireEye APT30 Report Sample"
      author = "Florian Roth"
      reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
      date = "2015-04-03 09:35:31"
      score = 65
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "49aca228674651cba776be727bdb7e60"
      hash2 = "5c7a6b3d1b85fad17333e02608844703"
      hash3 = "649fa64127fef1305ba141dd58fb83a5"
      tags = "APT, DEMO, FILE, G0013, GEN"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "Launcher.EXE" fullword wide
      $s1 = "Symantec Security Technologies" fullword wide
      $s2 = "\\Symantec LiveUpdate.lnk" ascii
      $s3 = "Symantec Service Framework" fullword wide
      $s4 = "\\ccSvcHst.exe" ascii
      $s5 = "\\wssfmgr.exe" ascii
      $s6 = "Symantec Corporation" fullword wide
      $s7 = "\\5.1.0.29" ascii
      $s8 = "\\Engine" ascii
      $s9 = "Copyright (C) 2000-2010 Symantec Corporation. All rights reserved." fullword wide
      $s10 = "Symantec LiveUpdate" fullword ascii
      $s11 = "\\Norton360" ascii
      $s15 = "BinRes" fullword ascii
      $s16 = "\\readme.lz" ascii
   condition: 
      filesize < 100KB and uint16 ( 0 ) == 0x5A4D and all of them
}