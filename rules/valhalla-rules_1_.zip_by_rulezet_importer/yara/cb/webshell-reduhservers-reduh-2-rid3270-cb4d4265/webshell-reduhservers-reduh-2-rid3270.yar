rule Webshell_reDuhServers_reDuh_2_RID3270 : CHINA DEMO T1505_003 WEBSHELL {
   meta:
      description = "Chinese Hacktool Set - file reDuh.php"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-13 14:05:11"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "errorlog(\"FRONTEND: send_command '\".$data.\"' on port \".$port.\" returned \"." ascii
      $s2 = "$msg = \"newData:\".$socketNumber.\":\".$targetHost.\":\".$targetPort.\":\".$seq" ascii
      $s3 = "errorlog(\"BACKEND: *** Socket key is \".$sockkey);" fullword ascii
   condition: 
      filesize < 57KB and all of them
}