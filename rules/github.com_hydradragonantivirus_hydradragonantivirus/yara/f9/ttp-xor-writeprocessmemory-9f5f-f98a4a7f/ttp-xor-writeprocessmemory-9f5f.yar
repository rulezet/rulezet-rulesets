rule TTP_XOR_WriteProcessMemory_9f5f {
  strings:
    $key_9f5f = { c8 2d [2] fa 0f [2] fc 3a [2] d2 3a [2] ed 26 }

  condition:
    any of them
}