rule TTP_XOR_WriteProcessMemory_b0b7 {
  strings:
    $key_b0b7 = { e7 c5 [2] d5 e7 [2] d3 d2 [2] fd d2 [2] c2 ce }

  condition:
    any of them
}