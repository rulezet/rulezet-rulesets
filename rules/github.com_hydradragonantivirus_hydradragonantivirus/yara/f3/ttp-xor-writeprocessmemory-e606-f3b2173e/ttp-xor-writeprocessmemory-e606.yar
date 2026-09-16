rule TTP_XOR_WriteProcessMemory_e606 {
  strings:
    $key_e606 = { b1 74 [2] 83 56 [2] 85 63 [2] ab 63 [2] 94 7f }

  condition:
    any of them
}