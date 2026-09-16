rule Webshell_JspSpy_xxx_RID2ED6 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Detects Web Shell from tennc webshell repo"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 11:31:31"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "76037ebd781ad0eac363d56fc81f4b4f"
      hash2 = "fc44f6b4387a2cb50e1a63c66a8cb81c"
      hash3 = "14e9688c86b454ed48171a9d4f48ace8"
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "\"<h2>Remote Control &raquo;</h2><input class=\\\"bt\\\" onclick=\\\"var" 
      $s2 = "\"<p>Current File (import new file name and new file)<br /><input class=\\\"inpu" 
      $s3 = "\"<p>Current file (fullpath)<br /><input class=\\\"input\\\" name=\\\"file\\\" i" 
   condition: 
      all of them
}