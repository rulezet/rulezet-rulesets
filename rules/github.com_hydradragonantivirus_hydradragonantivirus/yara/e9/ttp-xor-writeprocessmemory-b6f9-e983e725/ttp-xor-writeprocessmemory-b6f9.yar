rule TTP_XOR_WriteProcessMemory_b6f9 {
  strings:
    $key_b6f9 = { e1 8b [2] d3 a9 [2] d5 9c [2] fb 9c [2] c4 80 }

  condition:
    any of them
}