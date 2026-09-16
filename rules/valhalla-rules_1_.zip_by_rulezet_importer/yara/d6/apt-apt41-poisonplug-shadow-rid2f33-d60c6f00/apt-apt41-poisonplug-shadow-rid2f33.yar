import "pe"
rule APT_APT41_POISONPLUG_SHADOW_RID2F33 : APT DEMO EXE FILE G0096 {
   meta:
      description = "Detects APT41 malware POISONPLUG SHADOW"
      author = "Florian Roth"
      reference = "https://www.fireeye.com/blog/threat-research/2019/08/apt41-dual-espionage-and-cyber-crime-operation.html"
      date = "2019-08-07 11:47:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "462a02a8094e833fd456baf0a6d4e18bb7dab1a9f74d5f163a8334921a4ffde8"
      tags = "APT, DEMO, EXE, FILE, G0096"
      required_modules = "pe"
      minimum_yara = "3.5.0"
      
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 500KB and pe.imphash ( ) == "c67de089f2009b21715744762fc484e8"
}