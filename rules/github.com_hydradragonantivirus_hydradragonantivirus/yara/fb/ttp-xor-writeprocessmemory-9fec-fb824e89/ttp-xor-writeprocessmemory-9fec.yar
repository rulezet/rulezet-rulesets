rule TTP_XOR_WriteProcessMemory_9fec {
  strings:
    $key_9fec = { c8 9e [2] fa bc [2] fc 89 [2] d2 89 [2] ed 95 }

  condition:
    any of them
}