rule TTP_XOR_WriteProcessMemory_2c63 {
  strings:
    $key_2c63 = { 7b 11 [2] 49 33 [2] 4f 06 [2] 61 06 [2] 5e 1a }

  condition:
    any of them
}