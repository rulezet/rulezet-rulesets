rule TTP_XOR_WriteProcessMemory_b612 {
  strings:
    $key_b612 = { e1 60 [2] d3 42 [2] d5 77 [2] fb 77 [2] c4 6b }

  condition:
    any of them
}