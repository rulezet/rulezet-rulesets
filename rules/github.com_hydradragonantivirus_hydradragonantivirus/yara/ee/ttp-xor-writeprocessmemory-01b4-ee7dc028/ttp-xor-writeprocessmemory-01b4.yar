rule TTP_XOR_WriteProcessMemory_01b4 {
  strings:
    $key_01b4 = { 56 c6 [2] 64 e4 [2] 62 d1 [2] 4c d1 [2] 73 cd }

  condition:
    any of them
}