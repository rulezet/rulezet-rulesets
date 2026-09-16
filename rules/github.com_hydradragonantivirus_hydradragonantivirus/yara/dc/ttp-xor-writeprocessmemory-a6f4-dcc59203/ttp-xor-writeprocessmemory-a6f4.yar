rule TTP_XOR_WriteProcessMemory_a6f4 {
  strings:
    $key_a6f4 = { f1 86 [2] c3 a4 [2] c5 91 [2] eb 91 [2] d4 8d }

  condition:
    any of them
}