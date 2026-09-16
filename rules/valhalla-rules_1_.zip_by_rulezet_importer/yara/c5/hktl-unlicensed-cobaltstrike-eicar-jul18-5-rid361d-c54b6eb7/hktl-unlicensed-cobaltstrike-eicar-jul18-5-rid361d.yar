import "pe"
rule HKTL_Unlicensed_CobaltStrike_EICAR_Jul18_5_RID361D : APT COBALTSTRIKE DEMO EXE FILE G0079 HKTL MIDDLE_EAST S0154 T1550_002 {
   meta:
      description = "Detects strings found in malware samples in APT report in DarkHydrus"
      author = "Florian Roth"
      reference = "https://researchcenter.paloaltonetworks.com/2018/07/unit42-new-threat-actor-group-darkhydrus-targets-middle-east-government/"
      date = "2018-07-28 16:42:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2020-10-13"
      hash1 = "cec36e8ed65ac6f250c05b4a17c09f58bb80c19b73169aaf40fa15c8d3a9a6a1"
      tags = "APT, COBALTSTRIKE, DEMO, EXE, FILE, G0079, HKTL, MIDDLE_EAST, S0154, T1550_002"
      required_modules = "pe"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" 
      $s1 = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*" fullword ascii
      $s2 = "libgcj-12.dll" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 900KB and ( pe.imphash ( ) == "829da329ce140d873b4a8bde2cbfaa7e" or all of ( $s* ) or $x1 )
}