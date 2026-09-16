rule HKTL_Lazagne_Gen_18_RID2DA6 : DEMO GEN HKTL T1003 {
   meta:
      description = "Detects Lazagne password extractor hacktool"
      author = "Florian Roth"
      reference = "https://github.com/AlessandroZ/LaZagne"
      date = "2018-12-11 10:40:51"
      score = 80
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "51121dd5fbdfe8db7d3a5311e3e9c904d644ff7221b60284c03347938577eecf"
      tags = "DEMO, GEN, HKTL, T1003"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "lazagne.config.powershell_execute(" ascii
      $x2 = "creddump7.win32." ascii
      $x3 = "lazagne.softwares.windows.hashdump" ascii
      $x4 = ".softwares.memory.libkeepass.common(" ascii
   condition: 
      2 of them
}