rule TTP_XOR_WriteProcessMemory_cea4 {
  strings:
    $key_cea4 = { 99 d6 [2] ab f4 [2] ad c1 [2] 83 c1 [2] bc dd }

  condition:
    any of them
}