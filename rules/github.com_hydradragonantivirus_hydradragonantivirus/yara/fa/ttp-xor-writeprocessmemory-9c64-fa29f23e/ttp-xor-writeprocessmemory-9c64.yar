rule TTP_XOR_WriteProcessMemory_9c64 {
  strings:
    $key_9c64 = { cb 16 [2] f9 34 [2] ff 01 [2] d1 01 [2] ee 1d }

  condition:
    any of them
}