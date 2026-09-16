rule Nanocore_RAT_Sample_2 {
   meta:
      description = "Detetcs a certain Nanocore RAT sample"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      score = 75
      reference = "https://www.sentinelone.com/blogs/teaching-an-old-rat-new-tricks/"
      date = "2016-04-22"
      hash1 = "51142d1fb6c080b3b754a92e8f5826295f5da316ec72b480967cbd68432cede1"
      id = "81f6771a-29a3-5fa0-8d24-ea717d3c5251"
   strings:
      $s1 = "U4tSOtmpM" fullword ascii
      $s2 = ")U71UDAU_QU_YU_aU_iU_qU_yU_" wide
      $s3 = "Cy4tOtTmpMtTHVFOrR" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 40KB and all of ($s*)
}