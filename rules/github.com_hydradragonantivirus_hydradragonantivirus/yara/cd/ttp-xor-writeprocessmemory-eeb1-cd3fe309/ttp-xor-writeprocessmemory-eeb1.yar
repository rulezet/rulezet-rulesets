rule TTP_XOR_WriteProcessMemory_eeb1 {
  strings:
    $key_eeb1 = { b9 c3 [2] 8b e1 [2] 8d d4 [2] a3 d4 [2] 9c c8 }

  condition:
    any of them
}