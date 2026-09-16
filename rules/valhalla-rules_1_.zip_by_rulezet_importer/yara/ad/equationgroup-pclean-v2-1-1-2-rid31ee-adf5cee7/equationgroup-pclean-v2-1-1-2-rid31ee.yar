rule EquationGroup_pclean_v2_1_1_2_RID31EE : APT DEMO FILE G0020 LINUX {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- file pclean.v2.1.1.0-linux-i386"
      author = "Florian Roth"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08 13:43:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "cdb5b1173e6eb32b5ea494c38764b9975ddfe83aa09ba0634c4bafa41d844c97"
      tags = "APT, DEMO, FILE, G0020, LINUX"
      minimum_yara = "3.5.0"
      
   strings:
      $s3 = "** SIGNIFICANTLY IMPROVE PROCESSING TIME" fullword ascii
      $s6 = "-c cmd_name:     strncmp() search for 1st %d chars of commands that " fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x457f and filesize < 40KB and all of them )
}