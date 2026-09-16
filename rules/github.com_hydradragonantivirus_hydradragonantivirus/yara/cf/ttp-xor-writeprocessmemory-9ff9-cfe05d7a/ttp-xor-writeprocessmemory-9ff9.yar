rule TTP_XOR_WriteProcessMemory_9ff9 {
  strings:
    $key_9ff9 = { c8 8b [2] fa a9 [2] fc 9c [2] d2 9c [2] ed 80 }

  condition:
    any of them
}