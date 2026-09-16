rule TTP_XOR_WriteProcessMemory_81b6 {
  strings:
    $key_81b6 = { d6 c4 [2] e4 e6 [2] e2 d3 [2] cc d3 [2] f3 cf }

  condition:
    any of them
}