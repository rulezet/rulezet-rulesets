rule TTP_XOR_WriteProcessMemory_a162 {
  strings:
    $key_a162 = { f6 10 [2] c4 32 [2] c2 07 [2] ec 07 [2] d3 1b }

  condition:
    any of them
}