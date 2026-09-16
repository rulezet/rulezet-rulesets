rule Webshell_Java_Shell_js_RID2FBB : DEMO SCRIPT T1059_007 T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file Java Shell.js.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 12:09:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1059_007, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s2 = "PySystemState.initialize(System.getProperties(), null, argv);" fullword
      $s3 = "public class JythonShell extends JPanel implements Runnable {" fullword
      $s4 = "public static int DEFAULT_SCROLLBACK = 100" 
   condition: 
      2 of them
}