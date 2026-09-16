rule TTP_XOR_WriteProcessMemory_22b0 {
  strings:
    $key_22b0 = { 75 c2 [2] 47 e0 [2] 41 d5 [2] 6f d5 [2] 50 c9 }

  condition:
    any of them
}