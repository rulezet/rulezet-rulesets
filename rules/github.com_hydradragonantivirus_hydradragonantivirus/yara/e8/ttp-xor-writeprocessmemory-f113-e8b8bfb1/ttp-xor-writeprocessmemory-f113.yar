rule TTP_XOR_WriteProcessMemory_f113 {
  strings:
    $key_f113 = { a6 61 [2] 94 43 [2] 92 76 [2] bc 76 [2] 83 6a }

  condition:
    any of them
}