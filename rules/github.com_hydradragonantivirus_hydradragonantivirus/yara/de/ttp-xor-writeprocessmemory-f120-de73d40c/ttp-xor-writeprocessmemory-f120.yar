rule TTP_XOR_WriteProcessMemory_f120 {
  strings:
    $key_f120 = { a6 52 [2] 94 70 [2] 92 45 [2] bc 45 [2] 83 59 }

  condition:
    any of them
}