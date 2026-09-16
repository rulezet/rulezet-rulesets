rule TTP_XOR_WriteProcessMemory_9c5e {
  strings:
    $key_9c5e = { cb 2c [2] f9 0e [2] ff 3b [2] d1 3b [2] ee 27 }

  condition:
    any of them
}