rule TTP_XOR_WriteProcessMemory_7bd8 {
  strings:
    $key_7bd8 = { 2c aa [2] 1e 88 [2] 18 bd [2] 36 bd [2] 09 a1 }

  condition:
    any of them
}