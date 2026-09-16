rule HKTL_shelltools_g0t_root_HideRun_RID3387 : DEMO HKTL T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file HideRun.exe"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 14:51:41"
      score = 90
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, HKTL, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "Usage -- hiderun [AppName]" 
      $s7 = "PVAX SW, Alexey A. Popoff, Moscow, 1997." 
   condition: 
      all of them
}