rule TTP_XOR_WriteProcessMemory_6881 {
  strings:
    $key_6881 = { 3f f3 [2] 0d d1 [2] 0b e4 [2] 25 e4 [2] 1a f8 }

  condition:
    any of them
}