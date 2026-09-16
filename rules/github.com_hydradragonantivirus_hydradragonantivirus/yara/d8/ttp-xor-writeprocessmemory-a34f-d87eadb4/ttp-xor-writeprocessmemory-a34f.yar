rule TTP_XOR_WriteProcessMemory_a34f {
  strings:
    $key_a34f = { f4 3d [2] c6 1f [2] c0 2a [2] ee 2a [2] d1 36 }

  condition:
    any of them
}