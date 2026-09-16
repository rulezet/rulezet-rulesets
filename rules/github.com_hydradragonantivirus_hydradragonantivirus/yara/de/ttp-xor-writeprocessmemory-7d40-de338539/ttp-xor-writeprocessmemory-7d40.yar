rule TTP_XOR_WriteProcessMemory_7d40 {
  strings:
    $key_7d40 = { 2a 32 [2] 18 10 [2] 1e 25 [2] 30 25 [2] 0f 39 }

  condition:
    any of them
}