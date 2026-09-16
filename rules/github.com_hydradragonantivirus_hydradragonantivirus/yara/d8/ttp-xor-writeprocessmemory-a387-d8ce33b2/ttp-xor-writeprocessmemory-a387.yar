rule TTP_XOR_WriteProcessMemory_a387 {
  strings:
    $key_a387 = { f4 f5 [2] c6 d7 [2] c0 e2 [2] ee e2 [2] d1 fe }

  condition:
    any of them
}