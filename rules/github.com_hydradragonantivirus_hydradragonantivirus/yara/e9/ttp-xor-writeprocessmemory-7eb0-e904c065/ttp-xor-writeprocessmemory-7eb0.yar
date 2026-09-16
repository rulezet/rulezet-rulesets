rule TTP_XOR_WriteProcessMemory_7eb0 {
  strings:
    $key_7eb0 = { 29 c2 [2] 1b e0 [2] 1d d5 [2] 33 d5 [2] 0c c9 }

  condition:
    any of them
}