rule TTP_XOR_WriteProcessMemory_b662 {
  strings:
    $key_b662 = { e1 10 [2] d3 32 [2] d5 07 [2] fb 07 [2] c4 1b }

  condition:
    any of them
}