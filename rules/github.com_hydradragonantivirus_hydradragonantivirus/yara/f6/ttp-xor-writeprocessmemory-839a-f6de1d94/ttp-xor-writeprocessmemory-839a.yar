rule TTP_XOR_WriteProcessMemory_839a {
  strings:
    $key_839a = { d4 e8 [2] e6 ca [2] e0 ff [2] ce ff [2] f1 e3 }

  condition:
    any of them
}