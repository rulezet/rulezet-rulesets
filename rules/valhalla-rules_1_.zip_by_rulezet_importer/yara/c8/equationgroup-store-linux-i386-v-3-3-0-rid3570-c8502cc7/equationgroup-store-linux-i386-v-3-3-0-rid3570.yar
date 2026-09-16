rule EquationGroup_store_linux_i386_v_3_3_0_RID3570 : APT DEMO FILE G0020 LINUX {
   meta:
      description = "Equation Group hack tool set"
      author = "Florian Roth"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-09 16:13:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "abc27fda9a0921d7cf2863c29768af15fdfe47a0b3e7a131ef7e5cc057576fbc"
      tags = "APT, DEMO, FILE, G0020, LINUX"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "[-] Failed to map file: %s" fullword ascii
      $s2 = "[-] can not NULL terminate input data" fullword ascii
      $s3 = "[!] Name has size of 0!" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x457f and filesize < 60KB and all of them )
}