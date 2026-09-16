rule TTP_XOR_WriteProcessMemory_9f4b {
  strings:
    $key_9f4b = { c8 39 [2] fa 1b [2] fc 2e [2] d2 2e [2] ed 32 }

  condition:
    any of them
}