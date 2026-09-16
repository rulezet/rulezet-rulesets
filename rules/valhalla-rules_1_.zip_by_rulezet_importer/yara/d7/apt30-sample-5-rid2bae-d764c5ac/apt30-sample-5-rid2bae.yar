rule APT30_Sample_5_RID2BAE : APT DEMO FILE G0013 {
   meta:
      description = "FireEye APT30 Report Sample"
      author = "Florian Roth"
      reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
      date = "2015-04-03 09:16:51"
      score = 65
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "APT, DEMO, FILE, G0013"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "Version 4.7.3001" fullword wide
      $s1 = "Copyright (c) Microsoft Corporation 2004" fullword wide
      $s3 = "Microsoft(R) is a registered trademark of Microsoft Corporation in the U" wide
      $s7 = "msmsgs" fullword wide
      $s10 = "----------------g_nAV=%d,hWnd:0x%X,className:%s,Title:%s,(%d,%d,%d,%d),BOOL=%d" fullword ascii
   condition: 
      filesize < 100KB and uint16 ( 0 ) == 0x5A4D and all of them
}