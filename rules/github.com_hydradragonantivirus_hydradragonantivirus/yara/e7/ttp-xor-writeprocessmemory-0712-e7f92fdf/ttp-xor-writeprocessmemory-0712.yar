rule TTP_XOR_WriteProcessMemory_0712 {
  strings:
    $key_0712 = { 50 60 [2] 62 42 [2] 64 77 [2] 4a 77 [2] 75 6b }

  condition:
    any of them
}