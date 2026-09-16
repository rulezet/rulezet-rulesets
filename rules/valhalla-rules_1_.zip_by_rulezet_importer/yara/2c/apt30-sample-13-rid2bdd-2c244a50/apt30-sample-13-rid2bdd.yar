rule APT30_Sample_13_RID2BDD : APT DEMO FILE G0013 {
   meta:
      description = "FireEye APT30 Report Sample"
      author = "Florian Roth"
      reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
      date = "2015-04-03 09:24:41"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "APT, DEMO, FILE, G0013"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "msofscan.exe" fullword wide
      $s1 = "Microsoft? is a registered trademark of Microsoft Corporation." fullword wide
      $s2 = "Microsoft Office Word Plugin Scan" fullword wide
      $s3 = "? 2006 Microsoft Corporation.  All rights reserved." fullword wide
      $s4 = "msofscan" fullword wide
      $s6 = "2003 Microsoft Office system" fullword wide
   condition: 
      filesize < 100KB and uint16 ( 0 ) == 0x5A4D and all of them
}