rule TTP_XOR_WriteProcessMemory_1edf {
  strings:
    $key_1edf = { 49 ad [2] 7b 8f [2] 7d ba [2] 53 ba [2] 6c a6 }

  condition:
    any of them
}