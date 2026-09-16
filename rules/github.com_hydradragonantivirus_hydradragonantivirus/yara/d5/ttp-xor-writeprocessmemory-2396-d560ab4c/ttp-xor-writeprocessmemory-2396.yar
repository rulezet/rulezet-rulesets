rule TTP_XOR_WriteProcessMemory_2396 {
  strings:
    $key_2396 = { 74 e4 [2] 46 c6 [2] 40 f3 [2] 6e f3 [2] 51 ef }

  condition:
    any of them
}