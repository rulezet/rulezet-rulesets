rule TTP_XOR_WriteProcessMemory_96b6 {
  strings:
    $key_96b6 = { c1 c4 [2] f3 e6 [2] f5 d3 [2] db d3 [2] e4 cf }

  condition:
    any of them
}