rule Webshell_telnet_cgi_RID2EC4 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file telnet.cgi.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 11:28:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "W A R N I N G: Private Server" 
      $s2 = "print \"Set-Cookie: SAVEDPWD=;\\n\"; # remove password cookie" 
      $s3 = "$Prompt = $WinNT ? \"$CurrentDir> \" : \"[admin\\@$ServerName $C" 
   condition: 
      1 of them
}