rule TTP_XOR_WriteProcessMemory_a14d {
  strings:
    $key_a14d = { f6 3f [2] c4 1d [2] c2 28 [2] ec 28 [2] d3 34 }

  condition:
    any of them
}