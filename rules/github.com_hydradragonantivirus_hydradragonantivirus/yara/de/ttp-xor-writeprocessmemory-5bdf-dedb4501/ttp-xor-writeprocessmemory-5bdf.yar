rule TTP_XOR_WriteProcessMemory_5bdf {
  strings:
    $key_5bdf = { 0c ad [2] 3e 8f [2] 38 ba [2] 16 ba [2] 29 a6 }

  condition:
    any of them
}