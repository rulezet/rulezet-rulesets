rule CN_Honker_mempodipper2_6_RID3030 : CHINA DEMO HKTL {
   meta:
      description = "Sample from CN Honker Pentest Toolset - file mempodipper2.6.39"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 12:29:11"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "objdump -d /bin/su|grep '<exit@plt>'|head -n 1|cut -d ' ' -f 1|sed" ascii
   condition: 
      filesize < 30KB and all of them
}