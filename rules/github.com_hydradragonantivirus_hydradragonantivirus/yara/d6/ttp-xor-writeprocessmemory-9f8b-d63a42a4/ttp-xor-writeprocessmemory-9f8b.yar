rule TTP_XOR_WriteProcessMemory_9f8b {
  strings:
    $key_9f8b = { c8 f9 [2] fa db [2] fc ee [2] d2 ee [2] ed f2 }

  condition:
    any of them
}