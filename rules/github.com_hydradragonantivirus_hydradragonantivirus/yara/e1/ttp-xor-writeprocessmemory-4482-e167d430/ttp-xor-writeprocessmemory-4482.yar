rule TTP_XOR_WriteProcessMemory_4482 {
  strings:
    $key_4482 = { 13 f0 [2] 21 d2 [2] 27 e7 [2] 09 e7 [2] 36 fb }

  condition:
    any of them
}