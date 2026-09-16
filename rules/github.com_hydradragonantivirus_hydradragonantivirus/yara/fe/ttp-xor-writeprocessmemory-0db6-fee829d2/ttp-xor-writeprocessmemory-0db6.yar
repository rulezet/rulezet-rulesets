rule TTP_XOR_WriteProcessMemory_0db6 {
  strings:
    $key_0db6 = { 5a c4 [2] 68 e6 [2] 6e d3 [2] 40 d3 [2] 7f cf }

  condition:
    any of them
}