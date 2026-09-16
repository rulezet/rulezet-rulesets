rule TTP_XOR_WriteProcessMemory_a560 {
  strings:
    $key_a560 = { f2 12 [2] c0 30 [2] c6 05 [2] e8 05 [2] d7 19 }

  condition:
    any of them
}