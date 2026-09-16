rule TTP_XOR_WriteProcessMemory_b61e {
  strings:
    $key_b61e = { e1 6c [2] d3 4e [2] d5 7b [2] fb 7b [2] c4 67 }

  condition:
    any of them
}