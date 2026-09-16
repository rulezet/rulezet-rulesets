rule TTP_XOR_WriteProcessMemory_a2ce {
  strings:
    $key_a2ce = { f5 bc [2] c7 9e [2] c1 ab [2] ef ab [2] d0 b7 }

  condition:
    any of them
}