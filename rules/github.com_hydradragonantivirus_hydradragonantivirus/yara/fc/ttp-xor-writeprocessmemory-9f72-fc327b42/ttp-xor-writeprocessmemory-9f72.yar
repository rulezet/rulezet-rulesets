rule TTP_XOR_WriteProcessMemory_9f72 {
  strings:
    $key_9f72 = { c8 00 [2] fa 22 [2] fc 17 [2] d2 17 [2] ed 0b }

  condition:
    any of them
}