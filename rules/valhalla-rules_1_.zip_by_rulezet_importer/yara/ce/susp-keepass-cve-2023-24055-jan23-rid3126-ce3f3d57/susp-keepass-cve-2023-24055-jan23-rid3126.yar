rule SUSP_Keepass_CVE_2023_24055_Jan23_RID3126 : CVE_2023_24055 DEMO SUSP {
   meta:
      description = "Detects suspicious triggers defined in the Keepass configuration file, which could be indicator of the exploitation of CVE-2023-24055"
      author = "Florian Roth"
      reference = "https://github.com/alt3kx/CVE-2023-24055_PoC"
      date = "2023-01-25 13:10:11"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CVE_2023_24055, DEMO, SUSP"
      minimum_yara = "3.5.0"
      
   strings:
      $a1 = "<TriggerCollection xmlns:xsi=" ascii wide
      $s1 = "<Action>" ascii wide
      $s2 = "<Parameter>" ascii wide
   condition: 
      filesize < 200KB and $a1 and all of ( $s* )
}