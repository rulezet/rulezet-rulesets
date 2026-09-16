rule TTP_XOR_WriteProcessMemory_7db6 {
  strings:
    $key_7db6 = { 2a c4 [2] 18 e6 [2] 1e d3 [2] 30 d3 [2] 0f cf }

  condition:
    any of them
}