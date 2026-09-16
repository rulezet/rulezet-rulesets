rule TTP_XOR_WriteProcessMemory_a344 {
  strings:
    $key_a344 = { f4 36 [2] c6 14 [2] c0 21 [2] ee 21 [2] d1 3d }

  condition:
    any of them
}