rule Webshell_Txt_shell_RID2E5D : CHINA DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Chinese Hacktool Set - Webshells - file shell.c"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-14 11:11:21"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "printf(\"Could not connect to remote shell!\\n\");" fullword ascii
      $s2 = "printf(\"Usage: %s <reflect ip> <port>\\n\", prog);" fullword ascii
      $s3 = "execl(shell,\"/bin/sh\",(char *)0);" fullword ascii
      $s4 = "char shell[]=\"/bin/sh\";" fullword ascii
      $s5 = "connect back door\\n\\n\");" fullword ascii
   condition: 
      filesize < 2KB and 2 of them
}