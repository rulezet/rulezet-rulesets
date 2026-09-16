rule TTP_XOR_WriteProcessMemory_9f11 {
  strings:
    $key_9f11 = { c8 63 [2] fa 41 [2] fc 74 [2] d2 74 [2] ed 68 }

  condition:
    any of them
}