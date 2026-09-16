rule TTP_XOR_WriteProcessMemory_7296 {
  strings:
    $key_7296 = { 25 e4 [2] 17 c6 [2] 11 f3 [2] 3f f3 [2] 00 ef }

  condition:
    any of them
}