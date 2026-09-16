rule TTP_XOR_WriteProcessMemory_b635 {
  strings:
    $key_b635 = { e1 47 [2] d3 65 [2] d5 50 [2] fb 50 [2] c4 4c }

  condition:
    any of them
}