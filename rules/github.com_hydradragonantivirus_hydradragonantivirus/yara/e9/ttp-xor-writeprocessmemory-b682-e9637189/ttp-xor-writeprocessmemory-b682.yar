rule TTP_XOR_WriteProcessMemory_b682 {
  strings:
    $key_b682 = { e1 f0 [2] d3 d2 [2] d5 e7 [2] fb e7 [2] c4 fb }

  condition:
    any of them
}