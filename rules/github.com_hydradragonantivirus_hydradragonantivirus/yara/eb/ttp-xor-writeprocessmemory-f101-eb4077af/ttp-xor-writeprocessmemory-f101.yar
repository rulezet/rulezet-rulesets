rule TTP_XOR_WriteProcessMemory_f101 {
  strings:
    $key_f101 = { a6 73 [2] 94 51 [2] 92 64 [2] bc 64 [2] 83 78 }

  condition:
    any of them
}