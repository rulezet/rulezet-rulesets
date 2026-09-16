rule TTP_XOR_WriteProcessMemory_9f3d {
  strings:
    $key_9f3d = { c8 4f [2] fa 6d [2] fc 58 [2] d2 58 [2] ed 44 }

  condition:
    any of them
}