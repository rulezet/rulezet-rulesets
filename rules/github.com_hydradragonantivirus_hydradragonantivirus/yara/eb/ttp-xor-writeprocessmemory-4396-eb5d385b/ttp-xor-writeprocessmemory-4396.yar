rule TTP_XOR_WriteProcessMemory_4396 {
  strings:
    $key_4396 = { 14 e4 [2] 26 c6 [2] 20 f3 [2] 0e f3 [2] 31 ef }

  condition:
    any of them
}