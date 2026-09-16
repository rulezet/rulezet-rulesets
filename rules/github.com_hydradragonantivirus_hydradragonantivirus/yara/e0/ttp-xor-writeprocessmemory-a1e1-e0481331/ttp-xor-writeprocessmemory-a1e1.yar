rule TTP_XOR_WriteProcessMemory_a1e1 {
  strings:
    $key_a1e1 = { f6 93 [2] c4 b1 [2] c2 84 [2] ec 84 [2] d3 98 }

  condition:
    any of them
}