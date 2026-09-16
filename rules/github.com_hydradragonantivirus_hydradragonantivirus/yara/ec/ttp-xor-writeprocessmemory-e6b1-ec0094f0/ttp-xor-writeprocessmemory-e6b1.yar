rule TTP_XOR_WriteProcessMemory_e6b1 {
  strings:
    $key_e6b1 = { b1 c3 [2] 83 e1 [2] 85 d4 [2] ab d4 [2] 94 c8 }

  condition:
    any of them
}