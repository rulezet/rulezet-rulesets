rule Webshell_PHP_a_RID2C4E : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file a.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 09:43:31"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "echo \"<option value=\\\"\". strrev(substr(strstr(strrev($work_dir), \"/\"" 
      $s2 = "echo \"<option value=\\\"$work_dir\\\" selected>Current Directory</option>" 
      $s4 = "<input name=\"submit_btn\" type=\"submit\" value=\"Execute Command\"></p> " fullword
   condition: 
      2 of them
}