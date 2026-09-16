rule SUSP_JAVA_Class_with_VBS_Content {
   meta:
      description = "Detects a JAVA class file with strings known from VBS files"
      author = "Florian Roth"
      reference = "https://www.menlosecurity.com/blog/a-jar-full-of-problems-for-financial-services-companies"
      date = "2019-01-03"
      modified = "2025-03-20"
      score = 70
      hash1 = "e0112efb63f2b2ac3706109a233963c19750b4df0058cc5b9d3fa1f1280071eb"
      id = "472cbeaf-28e7-51a2-b2e6-96c1d9d05b26"
   strings:
      $a1 = "java/lang/String" ascii

      $s1 = ".vbs" ascii
      $s2 = "createNewFile" fullword ascii
      $s3 = "wscript" fullword ascii nocase

      $fp1 = "com/smm/"
      $fp2 = "install"
   condition:
      ( uint16(0) == 0xfeca or uint16(0) == 0xfacf or uint32(0) == 0xbebafeca ) 
      and filesize < 100KB 
      and $a1 
      and all of ($s*)
      and not 1 of ($fp*)
}