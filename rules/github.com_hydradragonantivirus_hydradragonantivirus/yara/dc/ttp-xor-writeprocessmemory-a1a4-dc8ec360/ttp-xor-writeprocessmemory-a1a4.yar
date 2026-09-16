rule TTP_XOR_WriteProcessMemory_a1a4 {
  strings:
    $key_a1a4 = { f6 d6 [2] c4 f4 [2] c2 c1 [2] ec c1 [2] d3 dd }

  condition:
    any of them
}