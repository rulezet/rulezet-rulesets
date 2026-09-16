rule TTP_XOR_WriteProcessMemory_f1c8 {
  strings:
    $key_f1c8 = { a6 ba [2] 94 98 [2] 92 ad [2] bc ad [2] 83 b1 }

  condition:
    any of them
}