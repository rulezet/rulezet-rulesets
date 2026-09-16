rule TTP_XOR_WriteProcessMemory_a324 {
  strings:
    $key_a324 = { f4 56 [2] c6 74 [2] c0 41 [2] ee 41 [2] d1 5d }

  condition:
    any of them
}