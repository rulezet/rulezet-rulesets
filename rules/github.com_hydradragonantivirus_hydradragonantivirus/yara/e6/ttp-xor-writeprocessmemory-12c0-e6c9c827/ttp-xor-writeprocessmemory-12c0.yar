rule TTP_XOR_WriteProcessMemory_12c0 {
  strings:
    $key_12c0 = { 45 b2 [2] 77 90 [2] 71 a5 [2] 5f a5 [2] 60 b9 }

  condition:
    any of them
}