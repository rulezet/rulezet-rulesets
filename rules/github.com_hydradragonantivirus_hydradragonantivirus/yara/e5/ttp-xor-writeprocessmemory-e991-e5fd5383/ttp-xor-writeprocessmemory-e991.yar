rule TTP_XOR_WriteProcessMemory_e991 {
  strings:
    $key_e991 = { be e3 [2] 8c c1 [2] 8a f4 [2] a4 f4 [2] 9b e8 }

  condition:
    any of them
}