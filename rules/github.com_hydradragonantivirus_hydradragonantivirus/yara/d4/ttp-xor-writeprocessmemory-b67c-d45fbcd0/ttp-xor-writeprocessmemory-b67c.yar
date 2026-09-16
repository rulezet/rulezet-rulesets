rule TTP_XOR_WriteProcessMemory_b67c {
  strings:
    $key_b67c = { e1 0e [2] d3 2c [2] d5 19 [2] fb 19 [2] c4 05 }

  condition:
    any of them
}