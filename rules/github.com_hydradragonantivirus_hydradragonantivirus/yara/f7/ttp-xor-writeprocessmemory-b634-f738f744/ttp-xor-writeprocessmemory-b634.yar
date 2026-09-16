rule TTP_XOR_WriteProcessMemory_b634 {
  strings:
    $key_b634 = { e1 46 [2] d3 64 [2] d5 51 [2] fb 51 [2] c4 4d }

  condition:
    any of them
}