rule TTP_XOR_WriteProcessMemory_a68c {
  strings:
    $key_a68c = { f1 fe [2] c3 dc [2] c5 e9 [2] eb e9 [2] d4 f5 }

  condition:
    any of them
}