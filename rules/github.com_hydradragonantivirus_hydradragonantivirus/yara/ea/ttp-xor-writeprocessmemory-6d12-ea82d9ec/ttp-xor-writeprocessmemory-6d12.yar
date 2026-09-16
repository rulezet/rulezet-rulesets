rule TTP_XOR_WriteProcessMemory_6d12 {
  strings:
    $key_6d12 = { 3a 60 [2] 08 42 [2] 0e 77 [2] 20 77 [2] 1f 6b }

  condition:
    any of them
}