rule TTP_XOR_WriteProcessMemory_6682 {
  strings:
    $key_6682 = { 31 f0 [2] 03 d2 [2] 05 e7 [2] 2b e7 [2] 14 fb }

  condition:
    any of them
}