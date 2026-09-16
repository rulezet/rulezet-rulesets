rule TTP_XOR_WriteProcessMemory_a1d4 {
  strings:
    $key_a1d4 = { f6 a6 [2] c4 84 [2] c2 b1 [2] ec b1 [2] d3 ad }

  condition:
    any of them
}