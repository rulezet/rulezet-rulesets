rule TTP_XOR_WriteProcessMemory_b63b {
  strings:
    $key_b63b = { e1 49 [2] d3 6b [2] d5 5e [2] fb 5e [2] c4 42 }

  condition:
    any of them
}