rule TTP_XOR_WriteProcessMemory_5718 {
  strings:
    $key_5718 = { 00 6a [2] 32 48 [2] 34 7d [2] 1a 7d [2] 25 61 }

  condition:
    any of them
}