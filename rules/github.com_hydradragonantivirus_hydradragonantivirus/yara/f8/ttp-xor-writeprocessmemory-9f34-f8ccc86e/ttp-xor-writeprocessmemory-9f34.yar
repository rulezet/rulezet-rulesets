rule TTP_XOR_WriteProcessMemory_9f34 {
  strings:
    $key_9f34 = { c8 46 [2] fa 64 [2] fc 51 [2] d2 51 [2] ed 4d }

  condition:
    any of them
}