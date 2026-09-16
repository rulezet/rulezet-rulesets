rule TTP_XOR_WriteProcessMemory_9ffa {
  strings:
    $key_9ffa = { c8 88 [2] fa aa [2] fc 9f [2] d2 9f [2] ed 83 }

  condition:
    any of them
}