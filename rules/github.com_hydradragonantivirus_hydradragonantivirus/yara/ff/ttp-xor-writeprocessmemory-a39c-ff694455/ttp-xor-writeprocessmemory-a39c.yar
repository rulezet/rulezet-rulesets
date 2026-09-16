rule TTP_XOR_WriteProcessMemory_a39c {
  strings:
    $key_a39c = { f4 ee [2] c6 cc [2] c0 f9 [2] ee f9 [2] d1 e5 }

  condition:
    any of them
}