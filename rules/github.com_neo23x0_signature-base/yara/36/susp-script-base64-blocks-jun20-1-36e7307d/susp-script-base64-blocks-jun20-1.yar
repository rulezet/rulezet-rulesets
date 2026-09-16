rule SUSP_Script_Base64_Blocks_Jun20_1 {
   meta:
      description = "Detects suspicious file with base64 encoded payload in blocks"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://posts.specterops.io/covenant-v0-5-eee0507b85ba"
      date = "2020-06-05"
      score = 70
      id = "cef759a5-b02a-53e7-bf27-184eee6bc3fa"
   strings:
      $sa1 = "<script language=" ascii
      $sb2 = { 41 41 41 22 2B 0D 0A 22 41 41 41 }
   condition:
      all of them
}