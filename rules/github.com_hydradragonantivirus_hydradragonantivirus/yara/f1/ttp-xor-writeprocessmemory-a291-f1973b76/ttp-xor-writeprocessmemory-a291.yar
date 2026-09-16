rule TTP_XOR_WriteProcessMemory_a291 {
  strings:
    $key_a291 = { f5 e3 [2] c7 c1 [2] c1 f4 [2] ef f4 [2] d0 e8 }

  condition:
    any of them
}