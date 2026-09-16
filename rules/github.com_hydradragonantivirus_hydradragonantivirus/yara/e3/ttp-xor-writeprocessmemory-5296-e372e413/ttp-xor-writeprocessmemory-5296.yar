rule TTP_XOR_WriteProcessMemory_5296 {
  strings:
    $key_5296 = { 05 e4 [2] 37 c6 [2] 31 f3 [2] 1f f3 [2] 20 ef }

  condition:
    any of them
}