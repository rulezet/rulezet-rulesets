rule TTP_XOR_WriteProcessMemory_9c5b {
  strings:
    $key_9c5b = { cb 29 [2] f9 0b [2] ff 3e [2] d1 3e [2] ee 22 }

  condition:
    any of them
}