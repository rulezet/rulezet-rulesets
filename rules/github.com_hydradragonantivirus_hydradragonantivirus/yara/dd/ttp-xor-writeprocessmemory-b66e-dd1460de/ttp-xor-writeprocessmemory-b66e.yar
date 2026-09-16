rule TTP_XOR_WriteProcessMemory_b66e {
  strings:
    $key_b66e = { e1 1c [2] d3 3e [2] d5 0b [2] fb 0b [2] c4 17 }

  condition:
    any of them
}