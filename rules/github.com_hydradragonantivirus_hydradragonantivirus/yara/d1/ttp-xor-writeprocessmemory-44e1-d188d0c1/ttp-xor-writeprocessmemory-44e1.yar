rule TTP_XOR_WriteProcessMemory_44e1 {
  strings:
    $key_44e1 = { 13 93 [2] 21 b1 [2] 27 84 [2] 09 84 [2] 36 98 }

  condition:
    any of them
}