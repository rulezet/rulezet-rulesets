rule TTP_XOR_WriteProcessMemory_4db6 {
  strings:
    $key_4db6 = { 1a c4 [2] 28 e6 [2] 2e d3 [2] 00 d3 [2] 3f cf }

  condition:
    any of them
}