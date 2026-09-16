rule TTP_XOR_WriteProcessMemory_12c1 {
  strings:
    $key_12c1 = { 45 b3 [2] 77 91 [2] 71 a4 [2] 5f a4 [2] 60 b8 }

  condition:
    any of them
}