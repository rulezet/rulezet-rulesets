rule TTP_XOR_WriteProcessMemory_88b6 {
  strings:
    $key_88b6 = { df c4 [2] ed e6 [2] eb d3 [2] c5 d3 [2] fa cf }

  condition:
    any of them
}