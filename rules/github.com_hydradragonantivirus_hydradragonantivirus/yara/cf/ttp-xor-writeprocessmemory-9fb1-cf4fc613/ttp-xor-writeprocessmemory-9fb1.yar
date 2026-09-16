rule TTP_XOR_WriteProcessMemory_9fb1 {
  strings:
    $key_9fb1 = { c8 c3 [2] fa e1 [2] fc d4 [2] d2 d4 [2] ed c8 }

  condition:
    any of them
}