rule TTP_XOR_WriteProcessMemory_7b96 {
  strings:
    $key_7b96 = { 2c e4 [2] 1e c6 [2] 18 f3 [2] 36 f3 [2] 09 ef }

  condition:
    any of them
}