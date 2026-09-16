rule Webshell_Antichat_Socks5_Server_php_php_RID368D : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file Antichat Socks5 Server.php.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 17:00:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "$port = base_convert(bin2hex(substr($reqmessage[$id], 3+$reqlen+1, 2)), 16, 10);" fullword
      $s3 = "#   [+] Domain name address type" 
      $s4 = "www.antichat.ru" 
   condition: 
      1 of them
}