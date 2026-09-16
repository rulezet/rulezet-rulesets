rule TTP_XOR_WriteProcessMemory_42b4 {
  strings:
    $key_42b4 = { 15 c6 [2] 27 e4 [2] 21 d1 [2] 0f d1 [2] 30 cd }

  condition:
    any of them
}