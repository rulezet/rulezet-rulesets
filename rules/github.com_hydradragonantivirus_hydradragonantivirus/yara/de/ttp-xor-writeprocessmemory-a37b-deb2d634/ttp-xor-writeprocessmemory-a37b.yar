rule TTP_XOR_WriteProcessMemory_a37b {
  strings:
    $key_a37b = { f4 09 [2] c6 2b [2] c0 1e [2] ee 1e [2] d1 02 }

  condition:
    any of them
}