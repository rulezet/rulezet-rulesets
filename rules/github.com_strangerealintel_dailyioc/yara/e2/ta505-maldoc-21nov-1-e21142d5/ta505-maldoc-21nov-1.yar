rule TA505_Maldoc_21Nov_1 {
   meta:
      description = "invitation.doc"
      author = "Arkbird_SOLG"
      reference = "https://twitter.com/58_158_177_102/status/1197432303057637377"
      date = "2019-11-21"
      hash1 = "a197c6de8734044c441438508dd3ce091252de4f98df2016b006a1c963c02505"
   strings:
      $x1 = "C:\\Users\\J\\AppData\\Local\\Microsoft\\Windows\\Temporary Internet Files\\Content.MSO\\basecamp" fullword wide
      $x2 = "*\\G{42DC991A-7E1B-4254-B210-CDD3DDCFD365}#2.0#0#C:\\Users\\1\\AppData\\Local\\Temp\\VBE\\MSForms.exd#Microsoft Forms 2.0 Object" wide
      $x3 = "*\\G{0D452EE1-E08F-101A-852E-02608C4D0BB4}#2.0#0#C:\\Windows\\system32\\FM20.DLL#Microsoft Forms 2.0 Object Library" fullword wide
      $x4 = "C:\\Users\\J\\AppData\\Local\\Temp\\basecamp" fullword wide
      $s5 = "*\\G{2DF8D04C-5BFA-101B-BDE5-00AA0044DE52}#2.8#0#C:\\Program Files\\Common Files\\Microsoft Shared\\OFFICE16\\MSO.DLL#Microsoft " wide
      $s6 = "*\\G{000204EF-0000-0000-C000-000000000046}#4.2#9#C:\\Program Files\\Common Files\\Microsoft Shared\\VBA\\VBA7.1\\VBE7.DLL#Visual" wide
      $s7 = "glColor.dll" fullword ascii
      $s8 = "magne.dll" fullword ascii
      $s9 = "InitScope.dll" fullword wide
      $s10 = "*\\G{00020430-0000-0000-C000-000000000046}#2.0#0#C:\\Windows\\system32\\stdole2.tlb#OLE Automation" fullword wide
      $s11 = "CopyFiles=@EP0NGJ8D.GPD,@EP0NGN8D.GPD,@EP0NGX8D.GPD,@EP0NCJ8D.CMB,@EP0NOJ8D.DXT,@EP0NOE10.DLL,@EP0NM4RC.DLL,@EP0NRE8D.DLL" fullword wide
      $s12 = "CopyFiles=@EP0NGJ8C.GPD,@EP0NGN8C.GPD,@EP0NGX8C.GPD,@EP0NCJ8C.CMB,@EP0NOJ8C.DXT,@EP0NOE09.DLL,@EP0NM4RB.DLL,@EP0NRE8C.DLL" fullword wide
      $s13 = "vspub2.dll-" fullword ascii
      $s14 = "pictarget" fullword ascii
      $s15 = "Public Declare Function ZooDcom Lib        \"vspub1.dll\" Alias \"IKAJSL\" () As Integer" fullword ascii
      $s16 = "\"Epson\"=\"http://go.microsoft.com/fwlink/?LinkID=36&prd=10798&sbp=Printers\"" fullword wide
      $s17 = "EP0NM4RC.DLL = 1" fullword wide
      $s18 = "EP0NOE10.DLL = 1" fullword wide
      $s19 = "EP0NRE8C.DLL = 1" fullword wide
      $s20 = "EP0NM4RB.DLL = 1" fullword wide
   condition:
      uint16(0) == 0xcfd0 and filesize < 3000KB and
      1 of ($x*) and 4 of them
}