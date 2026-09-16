rule TTP_XOR_WriteProcessMemory_44b1 {
  strings:
    $key_44b1 = { 13 c3 [2] 21 e1 [2] 27 d4 [2] 09 d4 [2] 36 c8 }

  condition:
    any of them
}