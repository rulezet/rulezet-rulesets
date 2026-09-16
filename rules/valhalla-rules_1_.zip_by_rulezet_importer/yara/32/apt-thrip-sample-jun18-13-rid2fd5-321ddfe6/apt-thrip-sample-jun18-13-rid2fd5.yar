import "pe"
rule APT_Thrip_Sample_Jun18_13_RID2FD5 : APT DEMO EXE FILE G0030 G0076 {
   meta:
      description = "Detects sample found in Thrip report by Symantec "
      author = "Florian Roth"
      reference = "https://www.symantec.com/blogs/threat-intelligence/thrip-hits-satellite-telecoms-defense-targets "
      date = "2018-06-21 12:14:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "780620521c92aab3d592b3dc149cbf58751ea285cfdaa50510002b441796b312"
      tags = "APT, DEMO, EXE, FILE, G0030, G0076"
      required_modules = "pe"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; AS; rv:11.0) like Gecko" fullword ascii
      $s2 = "<member><name>password</name>" fullword ascii
      $s3 = "<value><string>qqtorspy</string></value>" fullword ascii
      $s4 = "SOFTWARE\\QKitTORSPY" fullword wide
      $s5 = "ipecho.net" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 500KB and ( pe.imphash ( ) == "3dfad33b2fb66c083c99dc10341908b7" or 4 of them )
}