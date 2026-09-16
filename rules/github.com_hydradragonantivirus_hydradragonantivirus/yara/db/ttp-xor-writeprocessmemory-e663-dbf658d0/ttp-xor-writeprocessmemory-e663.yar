rule TTP_XOR_WriteProcessMemory_e663 {
  strings:
    $key_e663 = { b1 11 [2] 83 33 [2] 85 06 [2] ab 06 [2] 94 1a }

  condition:
    any of them
}