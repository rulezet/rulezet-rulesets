rule TTP_XOR_WriteProcessMemory_3367 {
  strings:
    $key_3367 = { 64 15 [2] 56 37 [2] 50 02 [2] 7e 02 [2] 41 1e }

  condition:
    any of them
}