rule TTP_XOR_WriteProcessMemory_f154 {
  strings:
    $key_f154 = { a6 26 [2] 94 04 [2] 92 31 [2] bc 31 [2] 83 2d }

  condition:
    any of them
}