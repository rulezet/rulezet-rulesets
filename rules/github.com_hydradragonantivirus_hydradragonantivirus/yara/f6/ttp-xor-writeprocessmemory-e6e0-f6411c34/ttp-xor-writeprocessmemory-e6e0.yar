rule TTP_XOR_WriteProcessMemory_e6e0 {
  strings:
    $key_e6e0 = { b1 92 [2] 83 b0 [2] 85 85 [2] ab 85 [2] 94 99 }

  condition:
    any of them
}