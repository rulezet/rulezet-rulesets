rule TTP_XOR_WriteProcessMemory_52c0 {
  strings:
    $key_52c0 = { 05 b2 [2] 37 90 [2] 31 a5 [2] 1f a5 [2] 20 b9 }

  condition:
    any of them
}