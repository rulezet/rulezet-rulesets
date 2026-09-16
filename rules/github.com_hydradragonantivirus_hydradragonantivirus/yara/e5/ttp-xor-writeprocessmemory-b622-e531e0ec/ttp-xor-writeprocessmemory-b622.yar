rule TTP_XOR_WriteProcessMemory_b622 {
  strings:
    $key_b622 = { e1 50 [2] d3 72 [2] d5 47 [2] fb 47 [2] c4 5b }

  condition:
    any of them
}