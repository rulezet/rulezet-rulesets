rule TTP_XOR_WriteProcessMemory_acb1 {
  strings:
    $key_acb1 = { fb c3 [2] c9 e1 [2] cf d4 [2] e1 d4 [2] de c8 }

  condition:
    any of them
}