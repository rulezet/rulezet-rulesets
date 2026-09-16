rule TTP_XOR_WriteProcessMemory_0cdf {
  strings:
    $key_0cdf = { 5b ad [2] 69 8f [2] 6f ba [2] 41 ba [2] 7e a6 }

  condition:
    any of them
}