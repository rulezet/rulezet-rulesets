rule TTP_XOR_WriteProcessMemory_f1ae {
  strings:
    $key_f1ae = { a6 dc [2] 94 fe [2] 92 cb [2] bc cb [2] 83 d7 }

  condition:
    any of them
}