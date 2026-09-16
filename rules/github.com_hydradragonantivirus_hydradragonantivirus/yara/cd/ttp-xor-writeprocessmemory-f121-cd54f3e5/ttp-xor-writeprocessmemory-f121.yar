rule TTP_XOR_WriteProcessMemory_f121 {
  strings:
    $key_f121 = { a6 53 [2] 94 71 [2] 92 44 [2] bc 44 [2] 83 58 }

  condition:
    any of them
}