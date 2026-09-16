rule TTP_XOR_WriteProcessMemory_acb3 {
  strings:
    $key_acb3 = { fb c1 [2] c9 e3 [2] cf d6 [2] e1 d6 [2] de ca }

  condition:
    any of them
}