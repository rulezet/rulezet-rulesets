rule TTP_XOR_WriteProcessMemory_9c16 {
  strings:
    $key_9c16 = { cb 64 [2] f9 46 [2] ff 73 [2] d1 73 [2] ee 6f }

  condition:
    any of them
}