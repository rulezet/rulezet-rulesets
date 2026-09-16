rule TTP_XOR_WriteProcessMemory_4d12 {
  strings:
    $key_4d12 = { 1a 60 [2] 28 42 [2] 2e 77 [2] 00 77 [2] 3f 6b }

  condition:
    any of them
}