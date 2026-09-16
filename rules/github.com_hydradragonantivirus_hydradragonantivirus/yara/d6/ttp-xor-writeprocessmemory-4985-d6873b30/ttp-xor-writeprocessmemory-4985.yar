rule TTP_XOR_WriteProcessMemory_4985 {
  strings:
    $key_4985 = { 1e f7 [2] 2c d5 [2] 2a e0 [2] 04 e0 [2] 3b fc }

  condition:
    any of them
}