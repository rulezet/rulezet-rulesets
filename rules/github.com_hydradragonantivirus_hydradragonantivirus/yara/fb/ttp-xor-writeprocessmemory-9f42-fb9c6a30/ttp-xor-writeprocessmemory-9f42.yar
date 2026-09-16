rule TTP_XOR_WriteProcessMemory_9f42 {
  strings:
    $key_9f42 = { c8 30 [2] fa 12 [2] fc 27 [2] d2 27 [2] ed 3b }

  condition:
    any of them
}