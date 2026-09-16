rule TTP_XOR_WriteProcessMemory_9f4a {
  strings:
    $key_9f4a = { c8 38 [2] fa 1a [2] fc 2f [2] d2 2f [2] ed 33 }

  condition:
    any of them
}