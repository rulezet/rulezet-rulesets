rule TTP_XOR_WriteProcessMemory_a1a2 {
  strings:
    $key_a1a2 = { f6 d0 [2] c4 f2 [2] c2 c7 [2] ec c7 [2] d3 db }

  condition:
    any of them
}