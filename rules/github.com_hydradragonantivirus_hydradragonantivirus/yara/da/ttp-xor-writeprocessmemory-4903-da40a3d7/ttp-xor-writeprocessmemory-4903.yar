rule TTP_XOR_WriteProcessMemory_4903 {
  strings:
    $key_4903 = { 1e 71 [2] 2c 53 [2] 2a 66 [2] 04 66 [2] 3b 7a }

  condition:
    any of them
}