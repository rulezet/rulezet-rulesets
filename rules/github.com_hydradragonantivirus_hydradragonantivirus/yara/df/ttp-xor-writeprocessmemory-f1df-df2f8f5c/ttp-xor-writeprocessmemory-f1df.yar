rule TTP_XOR_WriteProcessMemory_f1df {
  strings:
    $key_f1df = { a6 ad [2] 94 8f [2] 92 ba [2] bc ba [2] 83 a6 }

  condition:
    any of them
}