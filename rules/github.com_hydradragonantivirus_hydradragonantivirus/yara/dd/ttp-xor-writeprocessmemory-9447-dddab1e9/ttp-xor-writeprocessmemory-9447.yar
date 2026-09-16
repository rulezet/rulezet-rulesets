rule TTP_XOR_WriteProcessMemory_9447 {
  strings:
    $key_9447 = { c3 35 [2] f1 17 [2] f7 22 [2] d9 22 [2] e6 3e }

  condition:
    any of them
}