rule TTP_XOR_WriteProcessMemory_a453 {
  strings:
    $key_a453 = { f3 21 [2] c1 03 [2] c7 36 [2] e9 36 [2] d6 2a }

  condition:
    any of them
}