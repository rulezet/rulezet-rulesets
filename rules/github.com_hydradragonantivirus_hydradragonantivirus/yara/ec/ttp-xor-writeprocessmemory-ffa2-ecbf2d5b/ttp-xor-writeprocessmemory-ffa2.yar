rule TTP_XOR_WriteProcessMemory_ffa2 {
  strings:
    $key_ffa2 = { a8 d0 [2] 9a f2 [2] 9c c7 [2] b2 c7 [2] 8d db }

  condition:
    any of them
}