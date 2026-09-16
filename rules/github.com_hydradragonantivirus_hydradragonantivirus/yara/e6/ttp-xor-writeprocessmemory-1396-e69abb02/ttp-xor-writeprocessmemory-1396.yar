rule TTP_XOR_WriteProcessMemory_1396 {
  strings:
    $key_1396 = { 44 e4 [2] 76 c6 [2] 70 f3 [2] 5e f3 [2] 61 ef }

  condition:
    any of them
}