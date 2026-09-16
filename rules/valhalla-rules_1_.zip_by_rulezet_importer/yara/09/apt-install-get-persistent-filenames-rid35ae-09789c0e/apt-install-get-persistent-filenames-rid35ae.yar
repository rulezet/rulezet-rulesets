rule APT_install_get_persistent_filenames_RID35AE : APT DEMO FILE {
   meta:
      description = "EQGRP Toolset Firewall - file install_get_persistent_filenames"
      author = "Florian Roth"
      reference = "Research"
      date = "2016-08-16 16:23:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "4a50ec4bf42087e932e9e67e0ea4c09e52a475d351981bb4c9851fda02b35291"
      tags = "APT, DEMO, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "Generates the persistence file name and prints it out." fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x457f and all of them )
}