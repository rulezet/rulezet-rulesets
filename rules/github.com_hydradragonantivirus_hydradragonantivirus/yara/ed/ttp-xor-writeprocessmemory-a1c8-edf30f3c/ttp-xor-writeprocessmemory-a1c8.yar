rule TTP_XOR_WriteProcessMemory_a1c8 {
  strings:
    $key_a1c8 = { f6 ba [2] c4 98 [2] c2 ad [2] ec ad [2] d3 b1 }

  condition:
    any of them
}