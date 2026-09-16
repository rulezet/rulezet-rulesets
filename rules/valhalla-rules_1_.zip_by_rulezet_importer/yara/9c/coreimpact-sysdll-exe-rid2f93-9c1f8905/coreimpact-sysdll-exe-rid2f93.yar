rule CoreImpact_sysdll_exe_RID2F93 : APT DEMO G0130 MIDDLE_EAST {
   meta:
      description = "Detects a malware sysdll.exe from the Rocket Kitten APT"
      author = "Florian Roth"
      reference = "-"
      date = "2014-12-27 12:03:01"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2023-01-06"
      tags = "APT, DEMO, G0130, MIDDLE_EAST"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "d:\\nightly\\sandbox_avg10_vc9_SP1_2011\\source\\avg10\\avg9_all_vs90\\bin\\Rele" ascii
      $s1 = "Mozilla/5.0" fullword ascii
      $s3 = "index.php?c=%s&r=%lx" fullword ascii
      $s4 = "index.php?c=%s&r=%x" fullword ascii
      $s5 = "127.0.0.1" fullword ascii
      $s6 = "/info.dat" ascii
      $s7 = "needroot" fullword ascii
      $s8 = "./plugins/" ascii
   condition: 
      $s0 or 6 of them
}