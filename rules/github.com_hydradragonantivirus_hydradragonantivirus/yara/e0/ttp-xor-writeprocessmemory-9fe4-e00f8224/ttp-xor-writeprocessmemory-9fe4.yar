rule TTP_XOR_WriteProcessMemory_9fe4 {
  strings:
    $key_9fe4 = { c8 96 [2] fa b4 [2] fc 81 [2] d2 81 [2] ed 9d }

  condition:
    any of them
}