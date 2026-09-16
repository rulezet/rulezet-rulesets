rule HKTL_shelltools_g0t_root_uptime_RID336C : DEMO HKTL T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file uptime.exe"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-06 14:47:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, HKTL, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "JDiamondCSlC~" 
      $s1 = "CharactQA" 
      $s2 = "$Info: This file is packed with the UPX executable packer $" 
      $s5 = "HandlereateConso" 
      $s7 = "ION\\System\\FloatingPo" 
   condition: 
      all of them
}