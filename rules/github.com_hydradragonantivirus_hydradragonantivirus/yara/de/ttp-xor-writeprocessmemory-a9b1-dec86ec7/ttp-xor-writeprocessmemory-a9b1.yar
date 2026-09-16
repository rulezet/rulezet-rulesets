rule TTP_XOR_WriteProcessMemory_a9b1 {
  strings:
    $key_a9b1 = { fe c3 [2] cc e1 [2] ca d4 [2] e4 d4 [2] db c8 }

  condition:
    any of them
}