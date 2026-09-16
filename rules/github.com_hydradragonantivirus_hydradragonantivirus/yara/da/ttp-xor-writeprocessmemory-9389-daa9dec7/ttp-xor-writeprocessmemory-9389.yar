rule TTP_XOR_WriteProcessMemory_9389 {
  strings:
    $key_9389 = { c4 fb [2] f6 d9 [2] f0 ec [2] de ec [2] e1 f0 }

  condition:
    any of them
}