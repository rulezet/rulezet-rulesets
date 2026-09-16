rule TTP_XOR_WriteProcessMemory_03b6 {
  strings:
    $key_03b6 = { 54 c4 [2] 66 e6 [2] 60 d3 [2] 4e d3 [2] 71 cf }

  condition:
    any of them
}