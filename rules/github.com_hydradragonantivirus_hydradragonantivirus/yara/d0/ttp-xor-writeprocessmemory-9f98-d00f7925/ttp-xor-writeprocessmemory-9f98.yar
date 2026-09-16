rule TTP_XOR_WriteProcessMemory_9f98 {
  strings:
    $key_9f98 = { c8 ea [2] fa c8 [2] fc fd [2] d2 fd [2] ed e1 }

  condition:
    any of them
}