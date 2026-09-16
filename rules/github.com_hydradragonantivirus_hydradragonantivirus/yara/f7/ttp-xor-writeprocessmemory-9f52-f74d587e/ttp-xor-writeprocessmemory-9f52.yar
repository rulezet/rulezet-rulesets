rule TTP_XOR_WriteProcessMemory_9f52 {
  strings:
    $key_9f52 = { c8 20 [2] fa 02 [2] fc 37 [2] d2 37 [2] ed 2b }

  condition:
    any of them
}