rule TTP_XOR_WriteProcessMemory_9f08 {
  strings:
    $key_9f08 = { c8 7a [2] fa 58 [2] fc 6d [2] d2 6d [2] ed 71 }

  condition:
    any of them
}