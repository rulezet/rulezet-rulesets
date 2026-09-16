rule TTP_XOR_WriteProcessMemory_9f0d {
  strings:
    $key_9f0d = { c8 7f [2] fa 5d [2] fc 68 [2] d2 68 [2] ed 74 }

  condition:
    any of them
}