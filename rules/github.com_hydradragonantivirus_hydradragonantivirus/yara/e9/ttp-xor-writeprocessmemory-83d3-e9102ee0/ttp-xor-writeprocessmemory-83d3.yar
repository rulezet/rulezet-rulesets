rule TTP_XOR_WriteProcessMemory_83d3 {
  strings:
    $key_83d3 = { d4 a1 [2] e6 83 [2] e0 b6 [2] ce b6 [2] f1 aa }

  condition:
    any of them
}