rule TTP_XOR_WriteProcessMemory_9ce6 {
  strings:
    $key_9ce6 = { cb 94 [2] f9 b6 [2] ff 83 [2] d1 83 [2] ee 9f }

  condition:
    any of them
}