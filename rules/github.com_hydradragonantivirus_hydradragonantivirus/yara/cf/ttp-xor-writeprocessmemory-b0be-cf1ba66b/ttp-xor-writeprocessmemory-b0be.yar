rule TTP_XOR_WriteProcessMemory_b0be {
  strings:
    $key_b0be = { e7 cc [2] d5 ee [2] d3 db [2] fd db [2] c2 c7 }

  condition:
    any of them
}