rule TTP_XOR_WriteProcessMemory_31c0 {
  strings:
    $key_31c0 = { 66 b2 [2] 54 90 [2] 52 a5 [2] 7c a5 [2] 43 b9 }

  condition:
    any of them
}