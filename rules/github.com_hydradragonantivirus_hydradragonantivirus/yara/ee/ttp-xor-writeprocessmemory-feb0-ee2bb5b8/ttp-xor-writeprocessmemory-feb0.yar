rule TTP_XOR_WriteProcessMemory_feb0 {
  strings:
    $key_feb0 = { a9 c2 [2] 9b e0 [2] 9d d5 [2] b3 d5 [2] 8c c9 }

  condition:
    any of them
}