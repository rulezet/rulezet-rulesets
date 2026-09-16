rule WindowsCredentialEditor {
   meta:
      description = "Windows Credential Editor"
      threat_level = 10
      score = 90
      id = "1542c6e4-36b2-5272-85d0-43226869b43e"
   strings:
      $a = "extract the TGT session key"
      $b = "Windows Credentials Editor"
   condition:
      all of them
}