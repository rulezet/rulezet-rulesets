rule TTP_XOR_WriteProcessMemory_9f39 {
  strings:
    $key_9f39 = { c8 4b [2] fa 69 [2] fc 5c [2] d2 5c [2] ed 40 }

  condition:
    any of them
}