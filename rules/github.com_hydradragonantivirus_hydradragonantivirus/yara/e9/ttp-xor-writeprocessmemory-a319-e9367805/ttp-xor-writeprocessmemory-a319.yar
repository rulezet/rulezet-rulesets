rule TTP_XOR_WriteProcessMemory_a319 {
  strings:
    $key_a319 = { f4 6b [2] c6 49 [2] c0 7c [2] ee 7c [2] d1 60 }

  condition:
    any of them
}