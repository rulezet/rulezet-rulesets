rule TTP_XOR_WriteProcessMemory_44b0 {
  strings:
    $key_44b0 = { 13 c2 [2] 21 e0 [2] 27 d5 [2] 09 d5 [2] 36 c9 }

  condition:
    any of them
}