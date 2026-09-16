rule APT30_Sample_2_RID2BAB : APT DEMO FILE G0013 {
   meta:
      description = "FireEye APT30 Report Sample"
      author = "Florian Roth"
      reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
      date = "2015-04-03 09:16:21"
      score = 85
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "APT, DEMO, FILE, G0013"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "ForZRLnkWordDlg.EXE" fullword wide
      $s1 = "ForZRLnkWordDlg Microsoft " fullword wide
      $s9 = "ForZRLnkWordDlg 1.0 " fullword wide
      $s11 = "ForZRLnkWordDlg" fullword wide
      $s12 = " (C) 2011" fullword wide
   condition: 
      filesize < 100KB and uint16 ( 0 ) == 0x5A4D and all of them
}