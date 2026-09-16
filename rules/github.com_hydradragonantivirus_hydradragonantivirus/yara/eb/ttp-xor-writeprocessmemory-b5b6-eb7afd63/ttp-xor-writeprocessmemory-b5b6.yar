rule TTP_XOR_WriteProcessMemory_b5b6 {
  strings:
    $key_b5b6 = { e2 c4 [2] d0 e6 [2] d6 d3 [2] f8 d3 [2] c7 cf }

  condition:
    any of them
}