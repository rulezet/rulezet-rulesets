rule TTP_XOR_WriteProcessMemory_9710 {
  strings:
    $key_9710 = { c0 62 [2] f2 40 [2] f4 75 [2] da 75 [2] e5 69 }

  condition:
    any of them
}