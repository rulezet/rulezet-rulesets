rule TTP_XOR_WriteProcessMemory_b67e {
  strings:
    $key_b67e = { e1 0c [2] d3 2e [2] d5 1b [2] fb 1b [2] c4 07 }

  condition:
    any of them
}