rule TTP_XOR_WriteProcessMemory_acb2 {
  strings:
    $key_acb2 = { fb c0 [2] c9 e2 [2] cf d7 [2] e1 d7 [2] de cb }

  condition:
    any of them
}