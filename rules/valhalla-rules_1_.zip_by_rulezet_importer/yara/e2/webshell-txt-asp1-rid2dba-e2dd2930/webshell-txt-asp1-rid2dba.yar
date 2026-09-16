rule Webshell_Txt_asp1_RID2DBA : CHINA DEMO T1505_003 WEBSHELL {
   meta:
      description = "Chinese Hacktool Set - Webshells - file asp1.txt"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-14 10:44:11"
      score = 85
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "if ShellPath=\"\" Then ShellPath = \"cmd.exe\"" fullword ascii
      $s2 = "autoLoginEnable=WSHShell.RegRead(autoLoginPath & autoLoginEnableKey)" fullword ascii
      $s3 = "Set DD=CM.exec(ShellPath&\" /c \"&DefCmd)" fullword ascii
      $s4 = "szTempFile = server.mappath(\"cmd.txt\")" fullword ascii
   condition: 
      filesize < 70KB and 2 of them
}