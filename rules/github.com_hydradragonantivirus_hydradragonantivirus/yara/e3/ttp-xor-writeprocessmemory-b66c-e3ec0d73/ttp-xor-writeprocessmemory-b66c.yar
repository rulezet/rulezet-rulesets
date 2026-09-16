rule TTP_XOR_WriteProcessMemory_b66c {
  strings:
    $key_b66c = { e1 1e [2] d3 3c [2] d5 09 [2] fb 09 [2] c4 15 }

  condition:
    any of them
}