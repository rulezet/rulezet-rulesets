rule TTP_XOR_WriteProcessMemory_a603 {
  strings:
    $key_a603 = { f1 71 [2] c3 53 [2] c5 66 [2] eb 66 [2] d4 7a }

  condition:
    any of them
}