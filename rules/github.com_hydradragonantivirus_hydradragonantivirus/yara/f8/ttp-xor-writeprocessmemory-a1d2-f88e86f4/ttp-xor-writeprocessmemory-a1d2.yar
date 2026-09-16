rule TTP_XOR_WriteProcessMemory_a1d2 {
  strings:
    $key_a1d2 = { f6 a0 [2] c4 82 [2] c2 b7 [2] ec b7 [2] d3 ab }

  condition:
    any of them
}