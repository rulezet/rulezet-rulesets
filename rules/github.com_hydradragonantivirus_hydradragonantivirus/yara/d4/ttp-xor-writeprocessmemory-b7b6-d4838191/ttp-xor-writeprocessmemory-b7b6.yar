rule TTP_XOR_WriteProcessMemory_b7b6 {
  strings:
    $key_b7b6 = { e0 c4 [2] d2 e6 [2] d4 d3 [2] fa d3 [2] c5 cf }

  condition:
    any of them
}