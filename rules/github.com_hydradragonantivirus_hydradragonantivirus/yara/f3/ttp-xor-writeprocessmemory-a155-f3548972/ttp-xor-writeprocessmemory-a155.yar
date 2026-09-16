rule TTP_XOR_WriteProcessMemory_a155 {
  strings:
    $key_a155 = { f6 27 [2] c4 05 [2] c2 30 [2] ec 30 [2] d3 2c }

  condition:
    any of them
}