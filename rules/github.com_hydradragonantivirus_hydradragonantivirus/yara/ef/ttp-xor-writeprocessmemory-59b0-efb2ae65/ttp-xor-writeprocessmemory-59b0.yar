rule TTP_XOR_WriteProcessMemory_59b0 {
  strings:
    $key_59b0 = { 0e c2 [2] 3c e0 [2] 3a d5 [2] 14 d5 [2] 2b c9 }

  condition:
    any of them
}