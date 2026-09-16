rule TTP_XOR_WriteProcessMemory_a278 {
  strings:
    $key_a278 = { f5 0a [2] c7 28 [2] c1 1d [2] ef 1d [2] d0 01 }

  condition:
    any of them
}