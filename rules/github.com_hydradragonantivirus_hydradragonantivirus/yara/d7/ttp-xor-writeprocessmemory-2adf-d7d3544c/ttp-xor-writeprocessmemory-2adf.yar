rule TTP_XOR_WriteProcessMemory_2adf {
  strings:
    $key_2adf = { 7d ad [2] 4f 8f [2] 49 ba [2] 67 ba [2] 58 a6 }

  condition:
    any of them
}