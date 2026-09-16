rule TTP_XOR_WriteProcessMemory_ecdf {
  strings:
    $key_ecdf = { bb ad [2] 89 8f [2] 8f ba [2] a1 ba [2] 9e a6 }

  condition:
    any of them
}