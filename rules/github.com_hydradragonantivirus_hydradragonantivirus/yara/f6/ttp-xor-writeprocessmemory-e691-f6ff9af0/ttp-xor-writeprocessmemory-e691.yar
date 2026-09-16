rule TTP_XOR_WriteProcessMemory_e691 {
  strings:
    $key_e691 = { b1 e3 [2] 83 c1 [2] 85 f4 [2] ab f4 [2] 94 e8 }

  condition:
    any of them
}