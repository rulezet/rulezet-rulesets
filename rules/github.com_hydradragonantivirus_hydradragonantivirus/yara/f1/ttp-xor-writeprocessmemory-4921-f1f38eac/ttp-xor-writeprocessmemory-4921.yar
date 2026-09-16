rule TTP_XOR_WriteProcessMemory_4921 {
  strings:
    $key_4921 = { 1e 53 [2] 2c 71 [2] 2a 44 [2] 04 44 [2] 3b 58 }

  condition:
    any of them
}