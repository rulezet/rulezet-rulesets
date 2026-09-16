import "pe"
rule APT_Thrip_Sample_Jun18_9_RID2FAA : APT DEMO EXE FILE G0030 G0076 {
   meta:
      description = "Detects sample found in Thrip report by Symantec "
      author = "Florian Roth"
      reference = "https://www.symantec.com/blogs/threat-intelligence/thrip-hits-satellite-telecoms-defense-targets "
      date = "2018-06-21 12:06:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "8e6682bcc51643f02a864b042f7223b157823f3d890fe21d38caeb43500d923e"
      hash2 = "0c8ca0fd0ec246ef207b96a3aac5e94c9c368504905b0a033f11eef8c62fa14c"
      hash3 = "6d0a2c822e2bc37cc0cec35f040d3fec5090ef2775df658d3823e47a93a5fef3"
      tags = "APT, DEMO, EXE, FILE, G0030, G0076"
      required_modules = "pe"
      minimum_yara = "3.5.0"
      
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 100KB and ( pe.imphash ( ) == "a7f0714e82b3105031fa7bc89dfe7664" or pe.imphash ( ) == "8812ff21aeb160e8800257140acae54b" or pe.imphash ( ) == "44a1e904763fe2d0837c747c7061b010" or pe.imphash ( ) == "51a854d285aa12eb82e76e6e1be01573" or pe.imphash ( ) == "a1f457c8c549c5c430556bfe5887a4e6" )
}