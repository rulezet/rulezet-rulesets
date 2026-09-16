rule TTP_XOR_WriteProcessMemory_f886 {
  strings:
    $key_f886 = { af f4 [2] 9d d6 [2] 9b e3 [2] b5 e3 [2] 8a ff }

  condition:
    any of them
}