rule TTP_XOR_WriteProcessMemory_eeb4 {
  strings:
    $key_eeb4 = { b9 c6 [2] 8b e4 [2] 8d d1 [2] a3 d1 [2] 9c cd }

  condition:
    any of them
}