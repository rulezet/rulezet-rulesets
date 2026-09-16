rule TTP_XOR_WriteProcessMemory_a35f {
  strings:
    $key_a35f = { f4 2d [2] c6 0f [2] c0 3a [2] ee 3a [2] d1 26 }

  condition:
    any of them
}