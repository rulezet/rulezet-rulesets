rule TTP_XOR_WriteProcessMemory_b624 {
  strings:
    $key_b624 = { e1 56 [2] d3 74 [2] d5 41 [2] fb 41 [2] c4 5d }

  condition:
    any of them
}