rule TTP_XOR_WriteProcessMemory_42b6 {
  strings:
    $key_42b6 = { 15 c4 [2] 27 e6 [2] 21 d3 [2] 0f d3 [2] 30 cf }

  condition:
    any of them
}