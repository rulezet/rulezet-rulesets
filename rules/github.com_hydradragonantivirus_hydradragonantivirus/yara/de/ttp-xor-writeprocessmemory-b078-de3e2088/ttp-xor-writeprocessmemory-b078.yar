rule TTP_XOR_WriteProcessMemory_b078 {
  strings:
    $key_b078 = { e7 0a [2] d5 28 [2] d3 1d [2] fd 1d [2] c2 01 }

  condition:
    any of them
}