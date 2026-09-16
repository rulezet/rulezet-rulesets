rule TTP_XOR_WriteProcessMemory_9c4e {
  strings:
    $key_9c4e = { cb 3c [2] f9 1e [2] ff 2b [2] d1 2b [2] ee 37 }

  condition:
    any of them
}