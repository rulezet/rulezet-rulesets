rule TTP_XOR_WriteProcessMemory_f881 {
  strings:
    $key_f881 = { af f3 [2] 9d d1 [2] 9b e4 [2] b5 e4 [2] 8a f8 }

  condition:
    any of them
}