rule TTP_XOR_WriteProcessMemory_9f01 {
  strings:
    $key_9f01 = { c8 73 [2] fa 51 [2] fc 64 [2] d2 64 [2] ed 78 }

  condition:
    any of them
}