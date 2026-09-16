rule TTP_XOR_WriteProcessMemory_50a2 {
  strings:
    $key_50a2 = { 07 d0 [2] 35 f2 [2] 33 c7 [2] 1d c7 [2] 22 db }

  condition:
    any of them
}