rule TTP_XOR_WriteProcessMemory_a37d {
  strings:
    $key_a37d = { f4 0f [2] c6 2d [2] c0 18 [2] ee 18 [2] d1 04 }

  condition:
    any of them
}