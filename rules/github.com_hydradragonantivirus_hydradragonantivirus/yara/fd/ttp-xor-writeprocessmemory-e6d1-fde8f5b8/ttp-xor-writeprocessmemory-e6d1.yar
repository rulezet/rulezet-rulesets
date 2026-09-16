rule TTP_XOR_WriteProcessMemory_e6d1 {
  strings:
    $key_e6d1 = { b1 a3 [2] 83 81 [2] 85 b4 [2] ab b4 [2] 94 a8 }

  condition:
    any of them
}