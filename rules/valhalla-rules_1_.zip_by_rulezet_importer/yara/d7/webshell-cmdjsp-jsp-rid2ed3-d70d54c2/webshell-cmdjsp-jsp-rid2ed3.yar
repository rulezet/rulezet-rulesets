rule Webshell_cmdjsp_jsp_RID2ED3 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file cmdjsp.jsp.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 11:31:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "// note that linux = cmd and windows = \"cmd.exe /c + cmd\" " fullword
      $s1 = "Process p = Runtime.getRuntime().exec(\"cmd.exe /C \" + cmd);" fullword
      $s2 = "cmdjsp.jsp" 
      $s3 = "michaeldaw.org" fullword
   condition: 
      2 of them
}