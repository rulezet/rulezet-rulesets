rule TTP_XOR_WriteProcessMemory_9fea {
  strings:
    $key_9fea = { c8 98 [2] fa ba [2] fc 8f [2] d2 8f [2] ed 93 }

  condition:
    any of them
}