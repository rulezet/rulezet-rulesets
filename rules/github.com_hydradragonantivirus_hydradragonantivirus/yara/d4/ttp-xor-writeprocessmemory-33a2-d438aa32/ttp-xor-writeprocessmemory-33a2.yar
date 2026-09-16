rule TTP_XOR_WriteProcessMemory_33a2 {
  strings:
    $key_33a2 = { 64 d0 [2] 56 f2 [2] 50 c7 [2] 7e c7 [2] 41 db }

  condition:
    any of them
}