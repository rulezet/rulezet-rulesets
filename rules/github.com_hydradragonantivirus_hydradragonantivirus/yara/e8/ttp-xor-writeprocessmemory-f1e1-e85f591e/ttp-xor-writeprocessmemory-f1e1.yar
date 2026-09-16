rule TTP_XOR_WriteProcessMemory_f1e1 {
  strings:
    $key_f1e1 = { a6 93 [2] 94 b1 [2] 92 84 [2] bc 84 [2] 83 98 }

  condition:
    any of them
}