rule TTP_XOR_WriteProcessMemory_e9b4 {
  strings:
    $key_e9b4 = { be c6 [2] 8c e4 [2] 8a d1 [2] a4 d1 [2] 9b cd }

  condition:
    any of them
}