rule TTP_XOR_WriteProcessMemory_a654 {
  strings:
    $key_a654 = { f1 26 [2] c3 04 [2] c5 31 [2] eb 31 [2] d4 2d }

  condition:
    any of them
}