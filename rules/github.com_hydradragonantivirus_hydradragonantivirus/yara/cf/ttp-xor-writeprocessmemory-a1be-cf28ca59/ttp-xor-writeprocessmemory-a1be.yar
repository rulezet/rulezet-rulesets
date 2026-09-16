rule TTP_XOR_WriteProcessMemory_a1be {
  strings:
    $key_a1be = { f6 cc [2] c4 ee [2] c2 db [2] ec db [2] d3 c7 }

  condition:
    any of them
}