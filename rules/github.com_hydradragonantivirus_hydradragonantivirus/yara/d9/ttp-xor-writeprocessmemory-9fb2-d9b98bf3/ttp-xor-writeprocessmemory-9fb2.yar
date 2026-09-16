rule TTP_XOR_WriteProcessMemory_9fb2 {
  strings:
    $key_9fb2 = { c8 c0 [2] fa e2 [2] fc d7 [2] d2 d7 [2] ed cb }

  condition:
    any of them
}