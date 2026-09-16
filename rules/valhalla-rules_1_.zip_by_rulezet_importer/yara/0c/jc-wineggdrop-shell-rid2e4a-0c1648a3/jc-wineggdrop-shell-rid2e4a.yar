rule Jc_WinEggDrop_Shell_RID2E4A : DEMO SCRIPT SUSP {
   meta:
      description = "Disclosed hacktool set (old stuff) - file Jc.WinEggDrop Shell.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-11-23 11:08:11"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, SUSP"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "Sniffer.dll" fullword ascii
      $s4 = ":Execute net.exe user Administrator pass" fullword ascii
      $s5 = "Fport.exe or mport.exe " fullword ascii
      $s6 = ":Password Sniffering Is Running |Not Running " fullword ascii
      $s9 = ": The Terminal Service Port Has Been Set To NewPort" fullword ascii
      $s15 = ": Del www.exe                   " fullword ascii
      $s20 = ":Dir *.exe                    " fullword ascii
   condition: 
      2 of them
}