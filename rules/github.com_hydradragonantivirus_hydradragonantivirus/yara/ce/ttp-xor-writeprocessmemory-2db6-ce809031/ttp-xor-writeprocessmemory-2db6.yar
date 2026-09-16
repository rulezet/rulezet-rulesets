rule TTP_XOR_WriteProcessMemory_2db6 {
  strings:
    $key_2db6 = { 7a c4 [2] 48 e6 [2] 4e d3 [2] 60 d3 [2] 5f cf }

  condition:
    any of them
}