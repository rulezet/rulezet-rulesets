rule TTP_XOR_WriteProcessMemory_a9e1 {
  strings:
    $key_a9e1 = { fe 93 [2] cc b1 [2] ca 84 [2] e4 84 [2] db 98 }

  condition:
    any of them
}