rule TTP_XOR_WriteProcessMemory_2d97 {
  strings:
    $key_2d97 = { 7a e5 [2] 48 c7 [2] 4e f2 [2] 60 f2 [2] 5f ee }

  condition:
    any of them
}