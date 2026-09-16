rule TTP_XOR_WriteProcessMemory_32c0 {
  strings:
    $key_32c0 = { 65 b2 [2] 57 90 [2] 51 a5 [2] 7f a5 [2] 40 b9 }

  condition:
    any of them
}