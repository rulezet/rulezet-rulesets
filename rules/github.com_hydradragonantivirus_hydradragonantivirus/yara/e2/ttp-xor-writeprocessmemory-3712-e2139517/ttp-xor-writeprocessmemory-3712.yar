rule TTP_XOR_WriteProcessMemory_3712 {
  strings:
    $key_3712 = { 60 60 [2] 52 42 [2] 54 77 [2] 7a 77 [2] 45 6b }

  condition:
    any of them
}