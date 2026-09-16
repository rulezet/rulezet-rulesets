rule Webshell_down_rar_Folder_down_RID32D4 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file down.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 14:21:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "response.write \"<font color=blue size=2>NetBios Name: \\\\\"  & Snet.ComputerName &" 
   condition: 
      all of them
}