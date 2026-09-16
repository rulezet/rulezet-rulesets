rule Webshell_FeliksPack3___PHP_Shells_ssh_RID3532 : DEMO FILE T1021_004 T1505_003 WEBSHELL {
   meta:
      description = "Webshells PHP Webshell - file ssh.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-06 16:02:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, FILE, T1021_004, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "eval(gzinflate(str_rot13(base64_decode('" 
   condition: 
      all of them
}