rule TTP_XOR_WriteProcessMemory_3b96 {
  strings:
    $key_3b96 = { 6c e4 [2] 5e c6 [2] 58 f3 [2] 76 f3 [2] 49 ef }

  condition:
    any of them
}