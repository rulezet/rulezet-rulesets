rule TTP_XOR_WriteProcessMemory_7d08 {
  strings:
    $key_7d08 = { 2a 7a [2] 18 58 [2] 1e 6d [2] 30 6d [2] 0f 71 }

  condition:
    any of them
}