rule TTP_XOR_WriteProcessMemory_62b0 {
  strings:
    $key_62b0 = { 35 c2 [2] 07 e0 [2] 01 d5 [2] 2f d5 [2] 10 c9 }

  condition:
    any of them
}