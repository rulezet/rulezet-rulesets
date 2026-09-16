rule TTP_XOR_WriteProcessMemory_37e1 {
  strings:
    $key_37e1 = { 60 93 [2] 52 b1 [2] 54 84 [2] 7a 84 [2] 45 98 }

  condition:
    any of them
}