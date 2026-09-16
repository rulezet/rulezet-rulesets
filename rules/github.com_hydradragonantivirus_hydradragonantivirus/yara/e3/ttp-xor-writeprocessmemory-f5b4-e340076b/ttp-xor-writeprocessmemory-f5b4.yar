rule TTP_XOR_WriteProcessMemory_f5b4 {
  strings:
    $key_f5b4 = { a2 c6 [2] 90 e4 [2] 96 d1 [2] b8 d1 [2] 87 cd }

  condition:
    any of them
}