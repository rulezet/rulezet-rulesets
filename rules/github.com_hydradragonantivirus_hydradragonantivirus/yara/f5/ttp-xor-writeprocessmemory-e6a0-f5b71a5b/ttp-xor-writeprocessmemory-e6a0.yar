rule TTP_XOR_WriteProcessMemory_e6a0 {
  strings:
    $key_e6a0 = { b1 d2 [2] 83 f0 [2] 85 c5 [2] ab c5 [2] 94 d9 }

  condition:
    any of them
}