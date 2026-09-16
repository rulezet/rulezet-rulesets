rule TTP_XOR_WriteProcessMemory_1b96 {
  strings:
    $key_1b96 = { 4c e4 [2] 7e c6 [2] 78 f3 [2] 56 f3 [2] 69 ef }

  condition:
    any of them
}