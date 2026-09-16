rule TTP_XOR_WriteProcessMemory_a102 {
  strings:
    $key_a102 = { f6 70 [2] c4 52 [2] c2 67 [2] ec 67 [2] d3 7b }

  condition:
    any of them
}