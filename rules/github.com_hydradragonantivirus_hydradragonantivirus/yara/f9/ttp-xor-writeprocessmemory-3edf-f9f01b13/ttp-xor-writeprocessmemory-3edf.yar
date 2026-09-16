rule TTP_XOR_WriteProcessMemory_3edf {
  strings:
    $key_3edf = { 69 ad [2] 5b 8f [2] 5d ba [2] 73 ba [2] 4c a6 }

  condition:
    any of them
}