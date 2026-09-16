rule Webshell_DefaceKeeper_0_2_php_RID3201 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file DefaceKeeper_0.2.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 13:46:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "target fi1e:<br><input type=\"text\" name=\"target\" value=\"index.php\"></br>" fullword
      $s1 = "eval(base64_decode(\"ZXZhbChiYXNlNjRfZGVjb2RlKCJhV2R1YjNKbFgzVnpaWEpmWVdKdmNuUW9" 
      $s2 = "<img src=\"http://s43.radikal.ru/i101/1004/d8/ced1f6b2f5a9.png\" align=\"center" 
   condition: 
      1 of them
}