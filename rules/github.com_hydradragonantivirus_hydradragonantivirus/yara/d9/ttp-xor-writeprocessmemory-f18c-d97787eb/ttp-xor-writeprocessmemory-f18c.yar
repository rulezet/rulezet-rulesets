rule TTP_XOR_WriteProcessMemory_f18c {
  strings:
    $key_f18c = { a6 fe [2] 94 dc [2] 92 e9 [2] bc e9 [2] 83 f5 }

  condition:
    any of them
}