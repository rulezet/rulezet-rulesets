rule TTP_XOR_WriteProcessMemory_9457 {
  strings:
    $key_9457 = { c3 25 [2] f1 07 [2] f7 32 [2] d9 32 [2] e6 2e }

  condition:
    any of them
}