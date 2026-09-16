rule TTP_XOR_WriteProcessMemory_9f65 {
  strings:
    $key_9f65 = { c8 17 [2] fa 35 [2] fc 00 [2] d2 00 [2] ed 1c }

  condition:
    any of them
}