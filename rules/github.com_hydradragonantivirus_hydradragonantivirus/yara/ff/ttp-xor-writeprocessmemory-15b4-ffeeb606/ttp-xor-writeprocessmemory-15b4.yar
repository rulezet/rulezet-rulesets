rule TTP_XOR_WriteProcessMemory_15b4 {
  strings:
    $key_15b4 = { 42 c6 [2] 70 e4 [2] 76 d1 [2] 58 d1 [2] 67 cd }

  condition:
    any of them
}