rule TTP_XOR_WriteProcessMemory_a1c2 {
  strings:
    $key_a1c2 = { f6 b0 [2] c4 92 [2] c2 a7 [2] ec a7 [2] d3 bb }

  condition:
    any of them
}