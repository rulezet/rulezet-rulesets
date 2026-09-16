rule TTP_XOR_WriteProcessMemory_b683 {
  strings:
    $key_b683 = { e1 f1 [2] d3 d3 [2] d5 e6 [2] fb e6 [2] c4 fa }

  condition:
    any of them
}