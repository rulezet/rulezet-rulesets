rule TTP_XOR_WriteProcessMemory_9b44 {
  strings:
    $key_9b44 = { cc 36 [2] fe 14 [2] f8 21 [2] d6 21 [2] e9 3d }

  condition:
    any of them
}