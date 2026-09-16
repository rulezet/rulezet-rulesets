rule TTP_XOR_WriteProcessMemory_b6e3 {
  strings:
    $key_b6e3 = { e1 91 [2] d3 b3 [2] d5 86 [2] fb 86 [2] c4 9a }

  condition:
    any of them
}