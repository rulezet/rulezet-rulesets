rule TTP_XOR_WriteProcessMemory_a621 {
  strings:
    $key_a621 = { f1 53 [2] c3 71 [2] c5 44 [2] eb 44 [2] d4 58 }

  condition:
    any of them
}