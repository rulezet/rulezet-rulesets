rule TTP_XOR_WriteProcessMemory_b6b7 {
  strings:
    $key_b6b7 = { e1 c5 [2] d3 e7 [2] d5 d2 [2] fb d2 [2] c4 ce }

  condition:
    any of them
}