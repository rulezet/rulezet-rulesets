rule TTP_XOR_WriteProcessMemory_7edf {
  strings:
    $key_7edf = { 29 ad [2] 1b 8f [2] 1d ba [2] 33 ba [2] 0c a6 }

  condition:
    any of them
}