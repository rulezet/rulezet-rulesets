rule TTP_XOR_WriteProcessMemory_f991 {
  strings:
    $key_f991 = { ae e3 [2] 9c c1 [2] 9a f4 [2] b4 f4 [2] 8b e8 }

  condition:
    any of them
}