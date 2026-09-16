rule TTP_XOR_WriteProcessMemory_e9b1 {
  strings:
    $key_e9b1 = { be c3 [2] 8c e1 [2] 8a d4 [2] a4 d4 [2] 9b c8 }

  condition:
    any of them
}