rule TTP_XOR_WriteProcessMemory_b687 {
  strings:
    $key_b687 = { e1 f5 [2] d3 d7 [2] d5 e2 [2] fb e2 [2] c4 fe }

  condition:
    any of them
}