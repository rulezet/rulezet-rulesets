rule TTP_XOR_WriteProcessMemory_d8e1 {
  strings:
    $key_d8e1 = { 8f 93 [2] bd b1 [2] bb 84 [2] 95 84 [2] aa 98 }

  condition:
    any of them
}