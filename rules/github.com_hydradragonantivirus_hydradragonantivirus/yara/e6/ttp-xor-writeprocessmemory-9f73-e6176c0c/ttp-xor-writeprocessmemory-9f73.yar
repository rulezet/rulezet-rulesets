rule TTP_XOR_WriteProcessMemory_9f73 {
  strings:
    $key_9f73 = { c8 01 [2] fa 23 [2] fc 16 [2] d2 16 [2] ed 0a }

  condition:
    any of them
}