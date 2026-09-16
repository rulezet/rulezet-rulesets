rule TTP_XOR_WriteProcessMemory_4926 {
  strings:
    $key_4926 = { 1e 54 [2] 2c 76 [2] 2a 43 [2] 04 43 [2] 3b 5f }

  condition:
    any of them
}