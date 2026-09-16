rule TTP_XOR_WriteProcessMemory_b658 {
  strings:
    $key_b658 = { e1 2a [2] d3 08 [2] d5 3d [2] fb 3d [2] c4 21 }

  condition:
    any of them
}