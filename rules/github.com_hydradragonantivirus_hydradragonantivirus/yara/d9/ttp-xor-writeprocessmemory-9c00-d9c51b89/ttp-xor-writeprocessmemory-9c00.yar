rule TTP_XOR_WriteProcessMemory_9c00 {
  strings:
    $key_9c00 = { cb 72 [2] f9 50 [2] ff 65 [2] d1 65 [2] ee 79 }

  condition:
    any of them
}