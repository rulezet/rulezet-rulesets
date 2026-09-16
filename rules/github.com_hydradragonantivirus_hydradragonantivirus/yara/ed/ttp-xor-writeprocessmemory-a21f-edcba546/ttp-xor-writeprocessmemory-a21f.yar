rule TTP_XOR_WriteProcessMemory_a21f {
  strings:
    $key_a21f = { f5 6d [2] c7 4f [2] c1 7a [2] ef 7a [2] d0 66 }

  condition:
    any of them
}