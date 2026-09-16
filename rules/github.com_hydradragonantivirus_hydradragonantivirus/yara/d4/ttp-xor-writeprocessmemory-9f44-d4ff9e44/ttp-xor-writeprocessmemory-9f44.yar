rule TTP_XOR_WriteProcessMemory_9f44 {
  strings:
    $key_9f44 = { c8 36 [2] fa 14 [2] fc 21 [2] d2 21 [2] ed 3d }

  condition:
    any of them
}