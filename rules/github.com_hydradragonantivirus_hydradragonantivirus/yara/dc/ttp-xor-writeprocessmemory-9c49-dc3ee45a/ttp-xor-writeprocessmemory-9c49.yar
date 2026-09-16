rule TTP_XOR_WriteProcessMemory_9c49 {
  strings:
    $key_9c49 = { cb 3b [2] f9 19 [2] ff 2c [2] d1 2c [2] ee 30 }

  condition:
    any of them
}