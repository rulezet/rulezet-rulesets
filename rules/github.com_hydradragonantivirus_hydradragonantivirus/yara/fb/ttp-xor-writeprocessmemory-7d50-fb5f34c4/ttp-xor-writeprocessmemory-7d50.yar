rule TTP_XOR_WriteProcessMemory_7d50 {
  strings:
    $key_7d50 = { 2a 22 [2] 18 00 [2] 1e 35 [2] 30 35 [2] 0f 29 }

  condition:
    any of them
}