rule TTP_XOR_WriteProcessMemory_9f51 {
  strings:
    $key_9f51 = { c8 23 [2] fa 01 [2] fc 34 [2] d2 34 [2] ed 28 }

  condition:
    any of them
}