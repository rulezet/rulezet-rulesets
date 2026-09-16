rule TTP_XOR_WriteProcessMemory_1ab4 {
  strings:
    $key_1ab4 = { 4d c6 [2] 7f e4 [2] 79 d1 [2] 57 d1 [2] 68 cd }

  condition:
    any of them
}