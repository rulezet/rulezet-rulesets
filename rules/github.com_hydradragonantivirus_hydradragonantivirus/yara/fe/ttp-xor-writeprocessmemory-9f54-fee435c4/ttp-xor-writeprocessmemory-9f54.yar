rule TTP_XOR_WriteProcessMemory_9f54 {
  strings:
    $key_9f54 = { c8 26 [2] fa 04 [2] fc 31 [2] d2 31 [2] ed 2d }

  condition:
    any of them
}