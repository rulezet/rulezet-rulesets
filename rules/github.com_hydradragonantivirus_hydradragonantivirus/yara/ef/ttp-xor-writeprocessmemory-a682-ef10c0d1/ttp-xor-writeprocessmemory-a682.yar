rule TTP_XOR_WriteProcessMemory_a682 {
  strings:
    $key_a682 = { f1 f0 [2] c3 d2 [2] c5 e7 [2] eb e7 [2] d4 fb }

  condition:
    any of them
}