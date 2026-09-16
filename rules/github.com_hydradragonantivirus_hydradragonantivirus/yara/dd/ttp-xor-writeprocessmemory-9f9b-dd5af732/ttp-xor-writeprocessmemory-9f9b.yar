rule TTP_XOR_WriteProcessMemory_9f9b {
  strings:
    $key_9f9b = { c8 e9 [2] fa cb [2] fc fe [2] d2 fe [2] ed e2 }

  condition:
    any of them
}