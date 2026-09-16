rule TTP_XOR_WriteProcessMemory_4886 {
  strings:
    $key_4886 = { 1f f4 [2] 2d d6 [2] 2b e3 [2] 05 e3 [2] 3a ff }

  condition:
    any of them
}