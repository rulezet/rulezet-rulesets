rule WebShell_c99_locus7s_RID2E8A : DEMO T1087_001 T1505_003 WEBSHELL {
   meta:
      description = "PHP Webshells Github Archive - file c99_locus7s.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-06 11:18:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1087_001, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s8 = "$encoded = base64_encode(file_get_contents($d.$f)); " fullword
      $s9 = "$file = $tmpdir.\"dump_\".getenv(\"SERVER_NAME\").\"_\".$db.\"_\".date(\"d-m-Y" 
      $s10 = "else {$tmp = htmlspecialchars(\"./dump_\".getenv(\"SERVER_NAME\").\"_\".$sq" 
      $s11 = "$c99sh_sourcesurl = \"http://locus7s.com/\"; //Sources-server " fullword
      $s19 = "$nixpwdperpage = 100; // Get first N lines from /etc/passwd " fullword
   condition: 
      2 of them
}