rule TTP_XOR_WriteProcessMemory_ff9c {
  strings:
    $key_ff9c = { a8 ee [2] 9a cc [2] 9c f9 [2] b2 f9 [2] 8d e5 }

  condition:
    any of them
}