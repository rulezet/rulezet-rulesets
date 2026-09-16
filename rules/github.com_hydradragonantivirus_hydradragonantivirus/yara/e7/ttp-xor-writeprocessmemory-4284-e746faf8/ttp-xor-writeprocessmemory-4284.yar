rule TTP_XOR_WriteProcessMemory_4284 {
  strings:
    $key_4284 = { 15 f6 [2] 27 d4 [2] 21 e1 [2] 0f e1 [2] 30 fd }

  condition:
    any of them
}