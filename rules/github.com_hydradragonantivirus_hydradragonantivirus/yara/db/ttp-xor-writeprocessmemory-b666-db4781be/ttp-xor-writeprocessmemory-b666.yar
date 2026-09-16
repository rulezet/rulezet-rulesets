rule TTP_XOR_WriteProcessMemory_b666 {
  strings:
    $key_b666 = { e1 14 [2] d3 36 [2] d5 03 [2] fb 03 [2] c4 1f }

  condition:
    any of them
}