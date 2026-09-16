rule TTP_XOR_WriteProcessMemory_a644 {
  strings:
    $key_a644 = { f1 36 [2] c3 14 [2] c5 21 [2] eb 21 [2] d4 3d }

  condition:
    any of them
}