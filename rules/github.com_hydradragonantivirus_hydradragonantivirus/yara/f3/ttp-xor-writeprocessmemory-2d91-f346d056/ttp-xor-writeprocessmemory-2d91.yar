rule TTP_XOR_WriteProcessMemory_2d91 {
  strings:
    $key_2d91 = { 7a e3 [2] 48 c1 [2] 4e f4 [2] 60 f4 [2] 5f e8 }

  condition:
    any of them
}