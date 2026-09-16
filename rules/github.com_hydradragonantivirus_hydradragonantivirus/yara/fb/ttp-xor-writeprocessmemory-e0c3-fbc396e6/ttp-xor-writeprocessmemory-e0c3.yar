rule TTP_XOR_WriteProcessMemory_e0c3 {
  strings:
    $key_e0c3 = { b7 b1 [2] 85 93 [2] 83 a6 [2] ad a6 [2] 92 ba }

  condition:
    any of them
}