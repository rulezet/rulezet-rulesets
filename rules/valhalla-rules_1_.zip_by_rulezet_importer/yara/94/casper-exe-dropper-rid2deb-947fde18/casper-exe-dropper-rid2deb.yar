rule Casper_EXE_Dropper_RID2DEB : APT DEMO {
   meta:
      description = "Casper French Espionage Malware - Win32/ProxyBot.B - Dropper https://www.welivesecurity.com/2015/03/05/casper-malware-babar-bunny-another-espionage-cartoon/"
      author = "Florian Roth"
      reference = "https://www.welivesecurity.com/2015/03/05/casper-malware-babar-bunny-another-espionage-cartoon/"
      date = "2015-03-05 10:52:21"
      score = 80
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2024-07-19"
      tags = "APT, DEMO"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "<Command>" fullword ascii
      $s1 = "</Command>" fullword ascii
      $s2 = "\" /d \"" fullword ascii
      $s4 = "'%s' %s" fullword ascii
      $s5 = "nKERNEL32.DLL" fullword wide
      $s6 = "@ReturnValue" fullword wide
      $s7 = "ID: 0x%x" fullword ascii
      $s8 = "Name: %S" fullword ascii
   condition: 
      7 of them
}