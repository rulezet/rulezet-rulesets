rule TTP_XOR_WriteProcessMemory_a125 {
  strings:
    $key_a125 = { f6 57 [2] c4 75 [2] c2 40 [2] ec 40 [2] d3 5c }

  condition:
    any of them
}