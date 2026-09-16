rule APT_MAL_REvil_Kaseya_Jul21_2_RID30AB : APT DEMO EXE FILE MAL {
   meta:
      description = "Detects malware used in the Kaseya supply chain attack"
      author = "Florian Roth"
      reference = "https://doublepulsar.com/kaseya-supply-chain-attack-delivers-mass-ransomware-event-to-us-companies-76e4ec6ec64b"
      date = "2021-07-02 12:49:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "0496ca57e387b10dfdac809de8a4e039f68e8d66535d5d19ec76d39f7d0a4402"
      hash2 = "8dd620d9aeb35960bb766458c8890ede987c33d239cf730f93fe49d90ae759dd"
      hash3 = "cc0cdc6a3d843e22c98170713abf1d6ae06e8b5e34ed06ac3159adafe85e3bd6"
      tags = "APT, DEMO, EXE, FILE, MAL"
      minimum_yara = "3.5.0"
      
   strings:
      $opa1 = { 8b 4d fc 83 c1 01 89 4d fc 81 7d f0 ff 00 00 00 77 1? ba 01 00 00 00 6b c2 00 8b 4d 08 } 
      $opa2 = { 89 45 f0 8b 4d fc 83 c1 01 89 4d fc 81 7d f0 ff 00 00 00 77 1? ba 01 00 00 00 6b c2 00 } 
      $opa3 = { 83 c1 01 89 4d fc 81 7d f0 ff 00 00 00 77 1? ba 01 00 00 00 6b c2 00 8b 4d 08 0f b6 14 01 } 
      $opa4 = { 89 45 f4 8b 0d ?? ?0 07 10 89 4d f8 8b 15 ?? ?1 07 10 89 55 fc ff 75 fc ff 75 f8 ff 55 f4 } 
      $opb1 = { 18 00 10 bd 18 00 10 bd 18 00 10 0e 19 00 10 cc cc cc } 
      $opb2 = { 18 00 10 0e 19 00 10 cc cc cc cc 8b 44 24 04 } 
      $opb3 = { 10 c4 18 00 10 bd 18 00 10 bd 18 00 10 0e 19 00 10 cc cc } 
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 3000KB and ( 2 of ( $opa* ) or 3 of them )
}