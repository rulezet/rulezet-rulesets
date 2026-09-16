rule TTP_XOR_WriteProcessMemory_9f2f {
  strings:
    $key_9f2f = { c8 5d [2] fa 7f [2] fc 4a [2] d2 4a [2] ed 56 }

  condition:
    any of them
}