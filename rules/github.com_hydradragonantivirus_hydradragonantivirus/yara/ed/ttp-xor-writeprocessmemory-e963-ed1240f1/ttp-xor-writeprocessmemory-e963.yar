rule TTP_XOR_WriteProcessMemory_e963 {
  strings:
    $key_e963 = { be 11 [2] 8c 33 [2] 8a 06 [2] a4 06 [2] 9b 1a }

  condition:
    any of them
}