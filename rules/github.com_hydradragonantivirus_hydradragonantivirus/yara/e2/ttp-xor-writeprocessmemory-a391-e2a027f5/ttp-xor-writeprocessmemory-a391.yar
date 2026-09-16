rule TTP_XOR_WriteProcessMemory_a391 {
  strings:
    $key_a391 = { f4 e3 [2] c6 c1 [2] c0 f4 [2] ee f4 [2] d1 e8 }

  condition:
    any of them
}