rule MAL_ELF_VPNFilter_3_RID2D6C : APT DEMO FILE LINUX MAL {
   meta:
      description = "Detects VPNFilter malware"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2018-05-24 10:31:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "0e0094d9bd396a6594da8e21911a3982cd737b445f591581560d766755097d92"
      hash2 = "9683b04123d7e9fe4c8c26c69b09c2233f7e1440f828837422ce330040782d17"
      hash3 = "37e29b0ea7a9b97597385a12f525e13c3a7d02ba4161a6946f2a7d978cc045b4"
      tags = "APT, DEMO, FILE, LINUX, MAL"
      minimum_yara = "3.5.0"
      
   strings:
      $sx1 = "User-Agent: Mozilla/6.1 (compatible; MSIE 9.0; Windows NT 5.3; Trident/5.0)" fullword ascii
      $sx2 = "Execute by shell[%d]:" fullword ascii
      $sx3 = "CONFIG.TOR.name:" fullword ascii
      $s1 = "Executing command:  %s %s..." fullword ascii
      $s2 = "/proc/%d/cmdline" fullword ascii
      $a1 = "Mozilla/5.0 Firefox/50.0" fullword ascii
      $a2 = "Mozilla/5.0 (X11; Ubuntu; Linux i686; rv:52.0) Gecko/20100101 Firefox/52.0" fullword ascii
      $a3 = "Mozilla/5.0 (Windows NT 6.1; rv:52.0) Gecko/20100101 Firefox/52.0" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x457f and filesize < 1000KB and ( 1 of ( $sx* ) or 2 of ( $s* ) or 2 of ( $a* ) )
}