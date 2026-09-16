rule TTP_XOR_WriteProcessMemory_8d6d {
  strings:
    $key_8d6d = { da 1f [2] e8 3d [2] ee 08 [2] c0 08 [2] ff 14 }

  condition:
    any of them
}