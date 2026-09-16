rule TTP_XOR_WriteProcessMemory_a9b6 {
  strings:
    $key_a9b6 = { fe c4 [2] cc e6 [2] ca d3 [2] e4 d3 [2] db cf }

  condition:
    any of them
}