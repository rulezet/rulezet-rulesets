rule TTP_XOR_WriteProcessMemory_9357 {
  strings:
    $key_9357 = { c4 25 [2] f6 07 [2] f0 32 [2] de 32 [2] e1 2e }

  condition:
    any of them
}