rule TTP_XOR_WriteProcessMemory_56b0 {
  strings:
    $key_56b0 = { 01 c2 [2] 33 e0 [2] 35 d5 [2] 1b d5 [2] 24 c9 }

  condition:
    any of them
}