rule GoldDragon_Aux_File_RID2E5E : APT CHINA CRIME DEMO {
   meta:
      description = "Detects export from Gold Dragon - February 2018"
      author = "Florian Roth"
      reference = "https://securingtomorrow.mcafee.com/mcafee-labs/gold-dragon-widens-olympics-malware-attacks-gains-permanent-presence-on-victims-systems/"
      date = "2018-02-03 11:11:31"
      score = 90
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "APT, CHINA, CRIME, DEMO"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "/////////////////////regkeyenum////////////" ascii
   condition: 
      filesize < 500KB and 1 of them
}