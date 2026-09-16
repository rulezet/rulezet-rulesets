rule TTP_XOR_WriteProcessMemory_9f4d {
  strings:
    $key_9f4d = { c8 3f [2] fa 1d [2] fc 28 [2] d2 28 [2] ed 34 }

  condition:
    any of them
}