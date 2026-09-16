rule SUSP_Script_Base64_Blocks_Jun20_1_RID32AF : DEMO SCRIPT SUSP T1132_001 {
   meta:
      description = "Detects suspicious file with base64 encoded payload in blocks"
      author = "Florian Roth"
      reference = "https://posts.specterops.io/covenant-v0-5-eee0507b85ba"
      date = "2020-06-05 14:15:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, SUSP, T1132_001"
      minimum_yara = "3.5.0"
      
   strings:
      $sa1 = "<script language=" ascii
      $sb2 = { 41 41 41 22 2B 0D 0A 22 41 41 41 } 
   condition: 
      all of them
}