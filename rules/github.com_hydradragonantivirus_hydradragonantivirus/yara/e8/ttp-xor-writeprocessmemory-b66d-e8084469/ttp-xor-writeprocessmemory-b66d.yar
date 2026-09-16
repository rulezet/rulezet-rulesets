rule TTP_XOR_WriteProcessMemory_b66d {
  strings:
    $key_b66d = { e1 1f [2] d3 3d [2] d5 08 [2] fb 08 [2] c4 14 }

  condition:
    any of them
}