rule MAL_ELF_VPNFilter_2_RID2D6B : APT DEMO FILE LINUX MAL {
   meta:
      description = "Detects VPNFilter malware"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2018-05-24 10:31:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "50ac4fcd3fbc8abcaa766449841b3a0a684b3e217fc40935f1ac22c34c58a9ec"
      tags = "APT, DEMO, FILE, LINUX, MAL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "User-Agent: Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 5.2; Trident/4.0)" fullword ascii
      $s2 = "passwordPASSWORDpassword" fullword ascii
      $s3 = "/tmp/client.key" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x457f and filesize < 1000KB and all of them
}