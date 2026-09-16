rule TTP_XOR_WriteProcessMemory_acb0 {
  strings:
    $key_acb0 = { fb c2 [2] c9 e0 [2] cf d5 [2] e1 d5 [2] de c9 }

  condition:
    any of them
}