rule TTP_XOR_WriteProcessMemory_9f24 {
  strings:
    $key_9f24 = { c8 56 [2] fa 74 [2] fc 41 [2] d2 41 [2] ed 5d }

  condition:
    any of them
}