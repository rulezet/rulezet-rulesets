rule SUSP_JAVA_Class_with_VBS_Content_RID32D1 : DEMO FILE SCRIPT SUSP {
   meta:
      description = "Detects a JAVA class file with strings known from VBS files"
      author = "Florian Roth"
      reference = "https://www.menlosecurity.com/blog/a-jar-full-of-problems-for-financial-services-companies"
      date = "2019-01-03 14:21:21"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2025-03-20"
      hash1 = "e0112efb63f2b2ac3706109a233963c19750b4df0058cc5b9d3fa1f1280071eb"
      tags = "DEMO, FILE, SCRIPT, SUSP"
      minimum_yara = "3.5.0"
      
   strings:
      $a1 = "java/lang/String" ascii
      $s1 = ".vbs" ascii
      $s2 = "createNewFile" fullword ascii
      $s3 = "wscript" fullword ascii nocase
      $fp1 = "com/smm/" 
      $fp2 = "install" 
   condition: 
      ( uint16 ( 0 ) == 0xfeca or uint16 ( 0 ) == 0xfacf or uint32 ( 0 ) == 0xbebafeca ) and filesize < 100KB and $a1 and all of ( $s* ) and not 1 of ( $fp* )
}