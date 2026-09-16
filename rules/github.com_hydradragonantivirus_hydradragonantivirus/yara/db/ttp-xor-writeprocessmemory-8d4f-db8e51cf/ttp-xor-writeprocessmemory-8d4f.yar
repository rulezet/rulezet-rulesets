rule TTP_XOR_WriteProcessMemory_8d4f {
  strings:
    $key_8d4f = { da 3d [2] e8 1f [2] ee 2a [2] c0 2a [2] ff 36 }

  condition:
    any of them
}