import "pe"
rule ShadowPad_nssock2_RID2DAE : DEMO EXE FILE MAL {
   meta:
      description = "Detects malicious nssock2.dll from ShadowPad incident - file nssock2.dll"
      author = "Florian Roth"
      reference = "https://securelist.com/shadowpad-in-corporate-networks/81432/"
      date = "2017-08-15 10:42:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "462a02a8094e833fd456baf0a6d4e18bb7dab1a9f74d5f163a8334921a4ffde8"
      hash2 = "c45116a22cf5695b618fcdf1002619e8544ba015d06b2e1dbf47982600c7545f"
      hash3 = "696be784c67896b9239a8af0a167add72b1becd3ef98d03e99207a3d5734f6eb"
      tags = "DEMO, EXE, FILE, MAL"
      required_modules = "pe"
      minimum_yara = "3.5.0"
      
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 500KB and ( pe.imphash ( ) == "c67de089f2009b21715744762fc484e8" or pe.imphash ( ) == "11522f7d4b2fc05acba8f534ca1b828a" ) )
}