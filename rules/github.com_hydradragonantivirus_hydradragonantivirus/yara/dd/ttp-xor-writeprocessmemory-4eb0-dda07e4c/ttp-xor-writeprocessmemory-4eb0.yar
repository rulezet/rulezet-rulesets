rule TTP_XOR_WriteProcessMemory_4eb0 {
  strings:
    $key_4eb0 = { 19 c2 [2] 2b e0 [2] 2d d5 [2] 03 d5 [2] 3c c9 }

  condition:
    any of them
}