rule Webshell_Java_Shell_RID2E7F : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file Java Shell.jsp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 11:17:01"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s4 = "public JythonShell(int columns, int rows, int scrollback) {" fullword
      $s9 = "this(null, Py.getSystemState(), columns, rows, scrollback);" fullword
   condition: 
      1 of them
}