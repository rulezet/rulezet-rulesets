rule TTP_XOR_WriteProcessMemory_6880 {
  strings:
    $key_6880 = { 3f f2 [2] 0d d0 [2] 0b e5 [2] 25 e5 [2] 1a f9 }

  condition:
    any of them
}