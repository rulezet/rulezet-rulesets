rule TTP_XOR_WriteProcessMemory_8721 {
  strings:
    $key_8721 = { d0 53 [2] e2 71 [2] e4 44 [2] ca 44 [2] f5 58 }

  condition:
    any of them
}