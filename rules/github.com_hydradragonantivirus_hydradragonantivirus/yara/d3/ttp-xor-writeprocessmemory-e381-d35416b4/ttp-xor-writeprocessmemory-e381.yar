rule TTP_XOR_WriteProcessMemory_e381 {
  strings:
    $key_e381 = { b4 f3 [2] 86 d1 [2] 80 e4 [2] ae e4 [2] 91 f8 }

  condition:
    any of them
}