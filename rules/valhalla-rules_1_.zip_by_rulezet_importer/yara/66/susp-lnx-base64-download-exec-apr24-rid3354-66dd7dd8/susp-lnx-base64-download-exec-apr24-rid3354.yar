rule SUSP_LNX_Base64_Download_Exec_Apr24_RID3354 : DEMO LINUX SCRIPT SUSP T1105 T1132_001 {
   meta:
      description = "Detects suspicious base64 encoded shell commands used for downloading and executing further stages"
      author = "Paul Hager"
      reference = "Internal Research"
      date = "2024-04-18 14:43:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, LINUX, SCRIPT, SUSP, T1105, T1132_001"
      minimum_yara = "4.0.0"
      
   strings:
      $sa1 = "curl http" base64
      $sa2 = "wget http" base64
      $sb1 = "chmod 777 " base64
      $sb2 = "/tmp/" base64
   condition: 
      1 of ( $sa* ) and all of ( $sb* )
}