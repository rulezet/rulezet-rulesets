rule TTP_XOR_WriteProcessMemory_49c4 {
  strings:
    $key_49c4 = { 1e b6 [2] 2c 94 [2] 2a a1 [2] 04 a1 [2] 3b bd }

  condition:
    any of them
}