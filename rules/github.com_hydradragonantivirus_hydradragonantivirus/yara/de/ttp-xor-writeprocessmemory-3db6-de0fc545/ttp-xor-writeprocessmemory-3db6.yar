rule TTP_XOR_WriteProcessMemory_3db6 {
  strings:
    $key_3db6 = { 6a c4 [2] 58 e6 [2] 5e d3 [2] 70 d3 [2] 4f cf }

  condition:
    any of them
}