rule TTP_XOR_WriteProcessMemory_a1c1 {
  strings:
    $key_a1c1 = { f6 b3 [2] c4 91 [2] c2 a4 [2] ec a4 [2] d3 b8 }

  condition:
    any of them
}