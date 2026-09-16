rule Nanocore_RAT_Sample_2_RID2EDE : APT DEMO EXE FILE NanocoreRAT {
   meta:
      description = "Detetcs a certain Nanocore RAT sample"
      author = "Florian Roth"
      reference = "https://www.sentinelone.com/blogs/teaching-an-old-rat-new-tricks/"
      date = "2016-04-22 11:32:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "51142d1fb6c080b3b754a92e8f5826295f5da316ec72b480967cbd68432cede1"
      tags = "APT, DEMO, EXE, FILE, NanocoreRAT"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "U4tSOtmpM" fullword ascii
      $s2 = ")U71UDAU_QU_YU_aU_iU_qU_yU_" wide
      $s3 = "Cy4tOtTmpMtTHVFOrR" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 40KB and all of ( $s* )
}