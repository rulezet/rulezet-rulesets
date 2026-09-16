rule TTP_XOR_WriteProcessMemory_b048 {
  strings:
    $key_b048 = { e7 3a [2] d5 18 [2] d3 2d [2] fd 2d [2] c2 31 }

  condition:
    any of them
}