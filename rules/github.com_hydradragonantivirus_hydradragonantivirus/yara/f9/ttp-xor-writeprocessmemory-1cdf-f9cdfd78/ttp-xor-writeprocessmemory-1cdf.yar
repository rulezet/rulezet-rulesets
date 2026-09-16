rule TTP_XOR_WriteProcessMemory_1cdf {
  strings:
    $key_1cdf = { 4b ad [2] 79 8f [2] 7f ba [2] 51 ba [2] 6e a6 }

  condition:
    any of them
}