rule TTP_XOR_WriteProcessMemory_8663 {
  strings:
    $key_8663 = { d1 11 [2] e3 33 [2] e5 06 [2] cb 06 [2] f4 1a }

  condition:
    any of them
}