rule TTP_XOR_WriteProcessMemory_4281 {
  strings:
    $key_4281 = { 15 f3 [2] 27 d1 [2] 21 e4 [2] 0f e4 [2] 30 f8 }

  condition:
    any of them
}