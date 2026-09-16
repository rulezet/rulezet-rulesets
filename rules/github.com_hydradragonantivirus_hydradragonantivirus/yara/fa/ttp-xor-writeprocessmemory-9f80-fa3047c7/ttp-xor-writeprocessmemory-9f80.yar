rule TTP_XOR_WriteProcessMemory_9f80 {
  strings:
    $key_9f80 = { c8 f2 [2] fa d0 [2] fc e5 [2] d2 e5 [2] ed f9 }

  condition:
    any of them
}