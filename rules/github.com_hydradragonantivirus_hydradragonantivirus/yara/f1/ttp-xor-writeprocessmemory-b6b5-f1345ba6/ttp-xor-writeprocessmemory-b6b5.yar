rule TTP_XOR_WriteProcessMemory_b6b5 {
  strings:
    $key_b6b5 = { e1 c7 [2] d3 e5 [2] d5 d0 [2] fb d0 [2] c4 cc }

  condition:
    any of them
}