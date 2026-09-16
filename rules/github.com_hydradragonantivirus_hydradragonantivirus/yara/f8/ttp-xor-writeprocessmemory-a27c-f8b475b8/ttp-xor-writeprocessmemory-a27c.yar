rule TTP_XOR_WriteProcessMemory_a27c {
  strings:
    $key_a27c = { f5 0e [2] c7 2c [2] c1 19 [2] ef 19 [2] d0 05 }

  condition:
    any of them
}