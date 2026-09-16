rule TTP_XOR_WriteProcessMemory_9c0b {
  strings:
    $key_9c0b = { cb 79 [2] f9 5b [2] ff 6e [2] d1 6e [2] ee 72 }

  condition:
    any of them
}