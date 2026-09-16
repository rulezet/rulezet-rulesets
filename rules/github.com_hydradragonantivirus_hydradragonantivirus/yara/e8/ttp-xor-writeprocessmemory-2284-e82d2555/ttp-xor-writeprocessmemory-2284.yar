rule TTP_XOR_WriteProcessMemory_2284 {
  strings:
    $key_2284 = { 75 f6 [2] 47 d4 [2] 41 e1 [2] 6f e1 [2] 50 fd }

  condition:
    any of them
}