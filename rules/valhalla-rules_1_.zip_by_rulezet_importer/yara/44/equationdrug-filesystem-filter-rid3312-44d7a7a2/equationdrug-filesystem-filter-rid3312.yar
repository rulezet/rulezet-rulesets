rule EquationDrug_FileSystem_Filter_RID3312 : APT DEMO {
   meta:
      description = "EquationDrug - Filesystem filter driver volrec.sys, scsi2mgr.sys"
      author = "Florian Roth"
      reference = "http://securelist.com/blog/research/69203/inside-the-equationdrug-espionage-platform/"
      date = "2015-03-11 14:32:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "APT, DEMO"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "volrec.sys" fullword wide
      $s1 = "volrec.pdb" fullword ascii
      $s2 = "Volume recognizer driver" fullword wide
   condition: 
      all of them
}