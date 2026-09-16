rule Webshell_WinX_Shell_RID2E83 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file WinX Shell.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 11:17:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s5 = "print \"<font face=\\\"Verdana\\\" size=\\\"1\\\" color=\\\"#990000\\\">Filenam" 
      $s8 = "print \"<font face=\\\"Verdana\\\" size=\\\"1\\\" color=\\\"#990000\\\">File: </" 
   condition: 
      all of them
}