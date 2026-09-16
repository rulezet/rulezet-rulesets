rule TTP_XOR_WriteProcessMemory_a641 {
  strings:
    $key_a641 = { f1 33 [2] c3 11 [2] c5 24 [2] eb 24 [2] d4 38 }

  condition:
    any of them
}