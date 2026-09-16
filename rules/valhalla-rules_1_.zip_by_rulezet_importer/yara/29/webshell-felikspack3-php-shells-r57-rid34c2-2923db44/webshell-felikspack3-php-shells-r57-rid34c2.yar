rule Webshell_FeliksPack3___PHP_Shells_r57_RID34C2 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file r57.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 15:44:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "$sql = \"LOAD DATA INFILE \\\"\".$_POST['test3_file']." 
   condition: 
      all of them
}