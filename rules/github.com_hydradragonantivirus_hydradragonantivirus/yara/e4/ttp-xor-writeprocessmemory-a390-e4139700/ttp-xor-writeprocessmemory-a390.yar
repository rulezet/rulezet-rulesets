rule TTP_XOR_WriteProcessMemory_a390 {
  strings:
    $key_a390 = { f4 e2 [2] c6 c0 [2] c0 f5 [2] ee f5 [2] d1 e9 }

  condition:
    any of them
}