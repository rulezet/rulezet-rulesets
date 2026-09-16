rule TTP_XOR_WriteProcessMemory_a1e2 {
  strings:
    $key_a1e2 = { f6 90 [2] c4 b2 [2] c2 87 [2] ec 87 [2] d3 9b }

  condition:
    any of them
}