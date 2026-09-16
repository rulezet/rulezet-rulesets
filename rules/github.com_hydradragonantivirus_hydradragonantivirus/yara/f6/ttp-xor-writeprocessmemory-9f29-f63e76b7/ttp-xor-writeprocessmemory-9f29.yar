rule TTP_XOR_WriteProcessMemory_9f29 {
  strings:
    $key_9f29 = { c8 5b [2] fa 79 [2] fc 4c [2] d2 4c [2] ed 50 }

  condition:
    any of them
}