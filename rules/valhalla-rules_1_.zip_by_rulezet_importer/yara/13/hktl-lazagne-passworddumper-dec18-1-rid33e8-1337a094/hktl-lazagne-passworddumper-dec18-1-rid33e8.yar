rule HKTL_Lazagne_PasswordDumper_Dec18_1_RID33E8 : DEMO EXE FILE HKTL T1003 {
   meta:
      description = "Detects password dumper Lazagne often used by middle eastern threat groups"
      author = "Florian Roth"
      reference = "https://www.symantec.com/blogs/threat-intelligence/seedworm-espionage-group"
      date = "2018-12-11 15:07:51"
      score = 85
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "1205f5845035e3ee30f5a1ced5500d8345246ef4900bcb4ba67ef72c0f79966c"
      hash2 = "884e991d2066163e02472ea82d89b64e252537b28c58ad57d9d648b969de6a63"
      hash3 = "bf8f30031769aa880cdbe22bc0be32691d9f7913af75a5b68f8426d4f0c7be50"
      tags = "DEMO, EXE, FILE, HKTL, T1003"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "softwares.opera(" ascii
      $s2 = "softwares.mozilla(" ascii
      $s3 = "config.dico(" ascii
      $s4 = "softwares.chrome(" ascii
      $s5 = "softwares.outlook(" ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 17000KB and 1 of them
}