rule TTP_XOR_WriteProcessMemory_9414 {
  strings:
    $key_9414 = { c3 66 [2] f1 44 [2] f7 71 [2] d9 71 [2] e6 6d }

  condition:
    any of them
}