rule TTP_XOR_WriteProcessMemory_93d3 {
  strings:
    $key_93d3 = { c4 a1 [2] f6 83 [2] f0 b6 [2] de b6 [2] e1 aa }

  condition:
    any of them
}