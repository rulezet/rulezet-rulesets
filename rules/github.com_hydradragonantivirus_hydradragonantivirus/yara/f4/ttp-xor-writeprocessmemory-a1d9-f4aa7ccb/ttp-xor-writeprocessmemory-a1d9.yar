rule TTP_XOR_WriteProcessMemory_a1d9 {
  strings:
    $key_a1d9 = { f6 ab [2] c4 89 [2] c2 bc [2] ec bc [2] d3 a0 }

  condition:
    any of them
}