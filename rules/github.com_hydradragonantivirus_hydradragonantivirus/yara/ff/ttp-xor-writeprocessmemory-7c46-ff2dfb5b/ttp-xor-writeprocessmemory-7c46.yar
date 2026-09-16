rule TTP_XOR_WriteProcessMemory_7c46 {
  strings:
    $key_7c46 = { 2b 34 [2] 19 16 [2] 1f 23 [2] 31 23 [2] 0e 3f }

  condition:
    any of them
}