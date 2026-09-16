rule TTP_XOR_WriteProcessMemory_9cf6 {
  strings:
    $key_9cf6 = { cb 84 [2] f9 a6 [2] ff 93 [2] d1 93 [2] ee 8f }

  condition:
    any of them
}