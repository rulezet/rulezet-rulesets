rule TTP_XOR_WriteProcessMemory_1d12 {
  strings:
    $key_1d12 = { 4a 60 [2] 78 42 [2] 7e 77 [2] 50 77 [2] 6f 6b }

  condition:
    any of them
}