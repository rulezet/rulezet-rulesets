rule TTP_XOR_WriteProcessMemory_1d3a {
  strings:
    $key_1d3a = { 4a 48 [2] 78 6a [2] 7e 5f [2] 50 5f [2] 6f 43 }

  condition:
    any of them
}