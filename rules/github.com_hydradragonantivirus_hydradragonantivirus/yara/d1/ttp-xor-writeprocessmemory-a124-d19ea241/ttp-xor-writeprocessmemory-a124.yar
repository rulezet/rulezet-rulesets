rule TTP_XOR_WriteProcessMemory_a124 {
  strings:
    $key_a124 = { f6 56 [2] c4 74 [2] c2 41 [2] ec 41 [2] d3 5d }

  condition:
    any of them
}