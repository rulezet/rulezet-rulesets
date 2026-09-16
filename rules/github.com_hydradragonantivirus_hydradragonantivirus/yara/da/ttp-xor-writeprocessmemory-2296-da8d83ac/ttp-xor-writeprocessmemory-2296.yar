rule TTP_XOR_WriteProcessMemory_2296 {
  strings:
    $key_2296 = { 75 e4 [2] 47 c6 [2] 41 f3 [2] 6f f3 [2] 50 ef }

  condition:
    any of them
}