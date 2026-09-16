rule TTP_XOR_WriteProcessMemory_a524 {
  strings:
    $key_a524 = { f2 56 [2] c0 74 [2] c6 41 [2] e8 41 [2] d7 5d }

  condition:
    any of them
}