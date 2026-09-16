rule TTP_XOR_WriteProcessMemory_9b64 {
  strings:
    $key_9b64 = { cc 16 [2] fe 34 [2] f8 01 [2] d6 01 [2] e9 1d }

  condition:
    any of them
}