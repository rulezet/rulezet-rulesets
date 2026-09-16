rule Webshell_aspbackdoor_regdll_RID3208 : DEMO T1218_010 T1505_003 WEBSHELL {
   meta:
      description = "Disclosed hacktool set (old stuff) - file regdll.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-11-23 13:47:51"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1218_010, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "exitcode = oShell.Run(\"c:\\WINNT\\system32\\regsvr32.exe /u/s \" & strFile, 0, " ascii
      $s3 = "oShell.Run \"c:\\WINNT\\system32\\regsvr32.exe /u/s \" & strFile, 0, False" fullword ascii
      $s4 = "EchoB(\"regsvr32.exe exitcode = \" & exitcode)" fullword ascii
      $s5 = "Public Property Get oFS()" fullword ascii
   condition: 
      all of them
}