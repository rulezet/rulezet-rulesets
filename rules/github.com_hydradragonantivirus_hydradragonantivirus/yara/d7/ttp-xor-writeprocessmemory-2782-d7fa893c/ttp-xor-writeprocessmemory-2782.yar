rule TTP_XOR_WriteProcessMemory_2782 {
  strings:
    $key_2782 = { 70 f0 [2] 42 d2 [2] 44 e7 [2] 6a e7 [2] 55 fb }

  condition:
    any of them
}