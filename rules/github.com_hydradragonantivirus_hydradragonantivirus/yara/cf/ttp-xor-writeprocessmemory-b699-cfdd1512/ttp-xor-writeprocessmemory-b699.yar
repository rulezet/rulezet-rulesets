rule TTP_XOR_WriteProcessMemory_b699 {
  strings:
    $key_b699 = { e1 eb [2] d3 c9 [2] d5 fc [2] fb fc [2] c4 e0 }

  condition:
    any of them
}