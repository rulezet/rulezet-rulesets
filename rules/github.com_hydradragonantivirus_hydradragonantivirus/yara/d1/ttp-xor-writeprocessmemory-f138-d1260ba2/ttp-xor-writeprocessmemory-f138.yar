rule TTP_XOR_WriteProcessMemory_f138 {
  strings:
    $key_f138 = { a6 4a [2] 94 68 [2] 92 5d [2] bc 5d [2] 83 41 }

  condition:
    any of them
}