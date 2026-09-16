rule TTP_XOR_WriteProcessMemory_9f26 {
  strings:
    $key_9f26 = { c8 54 [2] fa 76 [2] fc 43 [2] d2 43 [2] ed 5f }

  condition:
    any of them
}