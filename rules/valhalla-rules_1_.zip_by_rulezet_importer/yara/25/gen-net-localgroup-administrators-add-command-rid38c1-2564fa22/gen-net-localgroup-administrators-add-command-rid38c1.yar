rule Gen_Net_LocalGroup_Administrators_Add_Command_RID38C1 : DEMO EXE FILE GEN SUSP {
   meta:
      description = "Detects an executable that contains a command to add a user account to the local administrators group"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-07-08 18:34:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, EXE, FILE, GEN, SUSP"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = /net localgroup administrators [a-zA-Z0-9]{1,16} \/add/ nocase ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 400KB and 1 of them )
}