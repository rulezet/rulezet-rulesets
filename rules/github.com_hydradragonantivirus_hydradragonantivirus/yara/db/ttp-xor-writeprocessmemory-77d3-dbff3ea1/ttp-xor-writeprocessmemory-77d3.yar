rule TTP_XOR_WriteProcessMemory_77d3 {
  strings:
    $key_77d3 = { 20 a1 [2] 12 83 [2] 14 b6 [2] 3a b6 [2] 05 aa }

  condition:
    any of them
}