rule TTP_XOR_WriteProcessMemory_74a2 {
  strings:
    $key_74a2 = { 23 d0 [2] 11 f2 [2] 17 c7 [2] 39 c7 [2] 06 db }

  condition:
    any of them
}