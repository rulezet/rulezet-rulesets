rule TTP_XOR_WriteProcessMemory_8243 {
  strings:
    $key_8243 = { d5 31 [2] e7 13 [2] e1 26 [2] cf 26 [2] f0 3a }

  condition:
    any of them
}