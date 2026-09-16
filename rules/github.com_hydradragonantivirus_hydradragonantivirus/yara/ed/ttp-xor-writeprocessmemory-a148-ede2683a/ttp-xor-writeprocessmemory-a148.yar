rule TTP_XOR_WriteProcessMemory_a148 {
  strings:
    $key_a148 = { f6 3a [2] c4 18 [2] c2 2d [2] ec 2d [2] d3 31 }

  condition:
    any of them
}