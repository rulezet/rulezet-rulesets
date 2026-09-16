rule TTP_XOR_WriteProcessMemory_e5b0 {
  strings:
    $key_e5b0 = { b2 c2 [2] 80 e0 [2] 86 d5 [2] a8 d5 [2] 97 c9 }

  condition:
    any of them
}