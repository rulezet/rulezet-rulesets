import "pe"
rule APT_DarkHydrus_Jul18_1_RID2ED9 : APT DEMO EXE FILE G0079 MIDDLE_EAST {
   meta:
      description = "Detects strings found in malware samples in APT report in DarkHydrus"
      author = "Florian Roth"
      reference = "https://researchcenter.paloaltonetworks.com/2018/07/unit42-new-threat-actor-group-darkhydrus-targets-middle-east-government/"
      date = "2018-07-28 11:32:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "99541ab28fc3328e25723607df4b0d9ea0a1af31b58e2da07eff9f15c4e6565c"
      tags = "APT, DEMO, EXE, FILE, G0079, MIDDLE_EAST"
      required_modules = "pe"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "Z:\\devcenter\\aggressor\\" ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 600KB and ( pe.imphash ( ) == "d3666d1cde4790b22b44ec35976687fb" or 1 of them )
}