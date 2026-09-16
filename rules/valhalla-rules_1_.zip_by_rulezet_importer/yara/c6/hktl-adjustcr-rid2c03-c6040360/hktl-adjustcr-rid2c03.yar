rule HKTL_adjustcr_RID2C03 : DEMO HKTL T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file adjustcr.exe"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 09:31:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, HKTL, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "$Info: This file is packed with the UPX executable packer $" 
      $s2 = "$License: NRV for UPX is distributed under special license $" 
      $s6 = "AdjustCR Carr" 
      $s7 = "ION\\System\\FloatingPo" 
   condition: 
      all of them
}