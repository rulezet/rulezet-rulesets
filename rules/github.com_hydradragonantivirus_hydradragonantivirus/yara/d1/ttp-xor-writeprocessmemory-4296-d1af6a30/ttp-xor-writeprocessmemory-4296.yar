rule TTP_XOR_WriteProcessMemory_4296 {
  strings:
    $key_4296 = { 15 e4 [2] 27 c6 [2] 21 f3 [2] 0f f3 [2] 30 ef }

  condition:
    any of them
}