rule TTP_XOR_WriteProcessMemory_9fe6 {
  strings:
    $key_9fe6 = { c8 94 [2] fa b6 [2] fc 83 [2] d2 83 [2] ed 9f }

  condition:
    any of them
}