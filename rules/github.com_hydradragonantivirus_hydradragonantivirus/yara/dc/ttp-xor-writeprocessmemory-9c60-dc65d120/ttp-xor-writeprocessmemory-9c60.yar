rule TTP_XOR_WriteProcessMemory_9c60 {
  strings:
    $key_9c60 = { cb 12 [2] f9 30 [2] ff 05 [2] d1 05 [2] ee 19 }

  condition:
    any of them
}