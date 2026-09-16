rule Webshell_phpshell_3_RID2E98 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file phpshell.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 11:21:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s3 = "<input name=\"submit_btn\" type=\"submit\" value=\"Execute Command\"></p>" 
      $s5 = "      echo \"<option value=\\\"$work_dir\\\" selected>Current Directory</option>\\n\";" 
   condition: 
      all of them
}