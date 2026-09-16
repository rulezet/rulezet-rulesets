rule TTP_XOR_WriteProcessMemory_7b63 {
  strings:
    $key_7b63 = { 2c 11 [2] 1e 33 [2] 18 06 [2] 36 06 [2] 09 1a }

  condition:
    any of them
}