rule TTP_XOR_WriteProcessMemory_37b1 {
  strings:
    $key_37b1 = { 60 c3 [2] 52 e1 [2] 54 d4 [2] 7a d4 [2] 45 c8 }

  condition:
    any of them
}