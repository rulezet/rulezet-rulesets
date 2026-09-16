rule TTP_XOR_WriteProcessMemory_5cdf {
  strings:
    $key_5cdf = { 0b ad [2] 39 8f [2] 3f ba [2] 11 ba [2] 2e a6 }

  condition:
    any of them
}