rule TTP_XOR_WriteProcessMemory_a314 {
  strings:
    $key_a314 = { f4 66 [2] c6 44 [2] c0 71 [2] ee 71 [2] d1 6d }

  condition:
    any of them
}