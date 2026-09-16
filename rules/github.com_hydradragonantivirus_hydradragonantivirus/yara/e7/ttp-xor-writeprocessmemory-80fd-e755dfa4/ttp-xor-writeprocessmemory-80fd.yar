rule TTP_XOR_WriteProcessMemory_80fd {
  strings:
    $key_80fd = { d7 8f [2] e5 ad [2] e3 98 [2] cd 98 [2] f2 84 }

  condition:
    any of them
}