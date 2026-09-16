rule TTP_XOR_WriteProcessMemory_b621 {
  strings:
    $key_b621 = { e1 53 [2] d3 71 [2] d5 44 [2] fb 44 [2] c4 58 }

  condition:
    any of them
}