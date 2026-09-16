rule TTP_XOR_WriteProcessMemory_a3b6 {
  strings:
    $key_a3b6 = { f4 c4 [2] c6 e6 [2] c0 d3 [2] ee d3 [2] d1 cf }

  condition:
    any of them
}