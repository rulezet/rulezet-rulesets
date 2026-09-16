rule SUSP_LNX_Base64_Download_Exec_Apr24 : SCRIPT {
   meta:
      description = "Detects suspicious base64 encoded shell commands used for downloading and executing further stages"
      author = "Paul Hager"
      date = "2024-04-18"
      reference = "Internal Research"
      score = 75
      id = "df8dddef-3c49-500c-abc8-7f7de5aa69ae"
   strings:
      $sa1 = "curl http" base64
      $sa2 = "wget http" base64
      
      $sb1 = "chmod 777 " base64
      $sb2 = "/tmp/" base64
   condition:
      1 of ($sa*)
      and all of ($sb*)
}