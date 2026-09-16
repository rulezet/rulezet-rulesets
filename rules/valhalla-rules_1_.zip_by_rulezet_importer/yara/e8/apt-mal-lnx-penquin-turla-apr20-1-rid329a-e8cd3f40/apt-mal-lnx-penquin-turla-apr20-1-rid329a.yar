rule APT_MAL_LNX_Penquin_Turla_Apr20_1_RID329A : APT DEMO FILE G0010 LINUX MAL RUSSIA {
   meta:
      description = "Detects Penquin Turla Linux malware"
      author = "Florian Roth"
      reference = "https://twitter.com/IntezerLabs/status/1247131160452509696"
      date = "2020-04-05 14:12:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "67d9556c695ef6c51abf6fbab17acb3466e3149cf4d20cb64d6d34dc969b6502"
      hash2 = "8ccc081d4940c5d8aa6b782c16ed82528c0885bbb08210a8d0a8c519c54215bc"
      tags = "APT, DEMO, FILE, G0010, LINUX, MAL, RUSSIA"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "/root/.hsperfdata" ascii fullword
      $s2 = "Desc|     Filename     |  size  |state|" ascii fullword
      $s3 = "IPv6 address %s not supported" ascii fullword
      $s4 = "File already exist on remote filesystem !" ascii fullword
      $s5 = "/tmp/.sync.pid" ascii fullword
      $s6 = "'gateway' supported only on ethernet/FDDI/token ring/802.11/ATM LANE/Fibre Channel" ascii fullword
   condition: 
      uint16 ( 0 ) == 0x457f and filesize < 5000KB and 4 of them
}