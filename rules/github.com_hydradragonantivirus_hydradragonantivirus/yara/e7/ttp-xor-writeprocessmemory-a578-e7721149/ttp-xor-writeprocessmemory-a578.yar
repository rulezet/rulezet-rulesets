rule TTP_XOR_WriteProcessMemory_a578 {
  strings:
    $key_a578 = { f2 0a [2] c0 28 [2] c6 1d [2] e8 1d [2] d7 01 }

  condition:
    any of them
}