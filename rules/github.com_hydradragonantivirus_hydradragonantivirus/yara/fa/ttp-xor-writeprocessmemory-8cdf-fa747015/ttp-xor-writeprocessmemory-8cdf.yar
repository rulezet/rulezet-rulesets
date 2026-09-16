rule TTP_XOR_WriteProcessMemory_8cdf {
  strings:
    $key_8cdf = { db ad [2] e9 8f [2] ef ba [2] c1 ba [2] fe a6 }

  condition:
    any of them
}