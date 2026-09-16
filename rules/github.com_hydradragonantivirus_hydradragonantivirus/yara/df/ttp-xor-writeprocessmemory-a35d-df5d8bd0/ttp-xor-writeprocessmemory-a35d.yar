rule TTP_XOR_WriteProcessMemory_a35d {
  strings:
    $key_a35d = { f4 2f [2] c6 0d [2] c0 38 [2] ee 38 [2] d1 24 }

  condition:
    any of them
}