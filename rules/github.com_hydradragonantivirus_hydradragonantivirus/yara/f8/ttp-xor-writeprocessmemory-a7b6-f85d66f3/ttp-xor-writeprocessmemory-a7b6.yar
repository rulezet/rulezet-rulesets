rule TTP_XOR_WriteProcessMemory_a7b6 {
  strings:
    $key_a7b6 = { f0 c4 [2] c2 e6 [2] c4 d3 [2] ea d3 [2] d5 cf }

  condition:
    any of them
}