rule TTP_XOR_WriteProcessMemory_7886 {
  strings:
    $key_7886 = { 2f f4 [2] 1d d6 [2] 1b e3 [2] 35 e3 [2] 0a ff }

  condition:
    any of them
}