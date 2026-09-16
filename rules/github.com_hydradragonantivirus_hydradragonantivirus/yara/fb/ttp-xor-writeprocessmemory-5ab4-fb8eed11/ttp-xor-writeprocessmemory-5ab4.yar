rule TTP_XOR_WriteProcessMemory_5ab4 {
  strings:
    $key_5ab4 = { 0d c6 [2] 3f e4 [2] 39 d1 [2] 17 d1 [2] 28 cd }

  condition:
    any of them
}