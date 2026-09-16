rule MAL_Rombertik_CarbonGrabber_RID3162 : DEMO EXE FILE MAL {
   meta:
      description = "Detects CarbonGrabber alias Rombertik - file Copy#064046.scr"
      author = "Florian Roth"
      reference = "http://blogs.cisco.com/security/talos/rombertik"
      date = "2015-05-05 13:20:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "2f9b26b90311e62662c5946a1ac600d2996d3758"
      hash2 = "aeb94064af2a6107a14fd32f39cb502e704cd0ab"
      hash3 = "c2005c8d1a79da5e02e6a15d00151018658c264c"
      tags = "DEMO, EXE, FILE, MAL"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "ZwGetWriteWatch" fullword ascii
      $x2 = "OutputDebugStringA" fullword ascii
      $x3 = "malwar" fullword ascii
      $x4 = "sampl" fullword ascii
      $x5 = "viru" fullword ascii
      $x6 = "sandb" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 5MB and all of them
}