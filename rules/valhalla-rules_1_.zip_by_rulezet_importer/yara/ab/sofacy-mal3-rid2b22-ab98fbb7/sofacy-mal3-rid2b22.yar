rule Sofacy_Mal3_RID2B22 : APT DEMO EXE FILE G0007 RUSSIA {
   meta:
      description = "Sofacy Group Malware Sample 3"
      author = "Florian Roth"
      reference = "http://dokumente.linksfraktion.de/inhalt/report-orig.pdf"
      date = "2015-06-19 08:53:31"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2023-01-06"
      tags = "APT, DEMO, EXE, FILE, G0007, RUSSIA"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "shell\\open\\command=\"System Volume Information\\USBGuard.exe\" install" fullword ascii
      $s2 = ".?AVAgentModuleRemoteKeyLogger@@" fullword ascii
      $s3 = "<font size=4 color=red>process isn't exist</font>" fullword ascii
      $s4 = "<font size=4 color=red>process is exist</font>" fullword ascii
      $s5 = ".winnt.check-fix.com" ascii
      $s6 = ".update.adobeincorp.com" ascii
      $s7 = ".microsoft.checkwinframe.com" ascii
      $s8 = "adobeincorp.com" fullword wide
      $s9 = "# EXC: HttpSender - Cannot create Get Channel!" fullword ascii
      $x1 = "User-Agent: Mozilla/5.0 (Windows NT 6.2; WOW64; rv:20.0) Gecko/20100101 Firefox/" wide
      $x2 = "User-Agent: Mozilla/5.0 (Windows NT 6.; WOW64; rv:20.0) Gecko/20100101 Firefox/2" wide
      $x3 = "C:\\Windows\\System32\\cmd.exe" fullword wide
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 300KB and ( 2 of ( $s* ) or ( 1 of ( $s* ) and all of ( $x* ) ) )
}