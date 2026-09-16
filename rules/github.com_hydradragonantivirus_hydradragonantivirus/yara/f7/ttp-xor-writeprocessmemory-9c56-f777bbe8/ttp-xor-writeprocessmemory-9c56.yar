rule TTP_XOR_WriteProcessMemory_9c56 {
  strings:
    $key_9c56 = { cb 24 [2] f9 06 [2] ff 33 [2] d1 33 [2] ee 2f }

  condition:
    any of them
}