rule TTP_XOR_WriteProcessMemory_9f21 {
  strings:
    $key_9f21 = { c8 53 [2] fa 71 [2] fc 44 [2] d2 44 [2] ed 58 }

  condition:
    any of them
}