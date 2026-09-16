rule TTP_XOR_WriteProcessMemory_ffa1 {
  strings:
    $key_ffa1 = { a8 d3 [2] 9a f1 [2] 9c c4 [2] b2 c4 [2] 8d d8 }

  condition:
    any of them
}