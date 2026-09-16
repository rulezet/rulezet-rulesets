rule TTP_XOR_WriteProcessMemory_a1d3 {
  strings:
    $key_a1d3 = { f6 a1 [2] c4 83 [2] c2 b6 [2] ec b6 [2] d3 aa }

  condition:
    any of them
}