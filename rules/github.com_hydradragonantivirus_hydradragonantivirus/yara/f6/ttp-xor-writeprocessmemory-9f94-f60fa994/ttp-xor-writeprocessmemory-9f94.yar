rule TTP_XOR_WriteProcessMemory_9f94 {
  strings:
    $key_9f94 = { c8 e6 [2] fa c4 [2] fc f1 [2] d2 f1 [2] ed ed }

  condition:
    any of them
}