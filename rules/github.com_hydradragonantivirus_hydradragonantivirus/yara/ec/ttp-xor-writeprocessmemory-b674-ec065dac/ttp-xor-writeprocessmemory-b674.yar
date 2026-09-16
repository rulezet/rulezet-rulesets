rule TTP_XOR_WriteProcessMemory_b674 {
  strings:
    $key_b674 = { e1 06 [2] d3 24 [2] d5 11 [2] fb 11 [2] c4 0d }

  condition:
    any of them
}