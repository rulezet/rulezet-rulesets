rule TTP_XOR_WriteProcessMemory_9f56 {
  strings:
    $key_9f56 = { c8 24 [2] fa 06 [2] fc 33 [2] d2 33 [2] ed 2f }

  condition:
    any of them
}