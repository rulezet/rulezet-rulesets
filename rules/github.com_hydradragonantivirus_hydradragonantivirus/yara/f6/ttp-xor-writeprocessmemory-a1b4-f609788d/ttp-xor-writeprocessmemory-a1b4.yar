rule TTP_XOR_WriteProcessMemory_a1b4 {
  strings:
    $key_a1b4 = { f6 c6 [2] c4 e4 [2] c2 d1 [2] ec d1 [2] d3 cd }

  condition:
    any of them
}