rule TTP_XOR_WriteProcessMemory_9f67 {
  strings:
    $key_9f67 = { c8 15 [2] fa 37 [2] fc 02 [2] d2 02 [2] ed 1e }

  condition:
    any of them
}