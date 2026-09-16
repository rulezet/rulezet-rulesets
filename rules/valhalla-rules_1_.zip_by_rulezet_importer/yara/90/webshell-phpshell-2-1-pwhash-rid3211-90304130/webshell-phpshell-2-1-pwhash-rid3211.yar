rule Webshell_phpshell_2_1_pwhash_RID3211 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file pwhash.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 13:49:21"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "<tt>&nbsp;</tt>\" (space), \"<tt>[</tt>\" (left bracket), \"<tt>|</tt>\" (pi" 
      $s3 = "word: \"<tt>null</tt>\", \"<tt>yes</tt>\", \"<tt>no</tt>\", \"<tt>true</tt>\"," 
   condition: 
      1 of them
}