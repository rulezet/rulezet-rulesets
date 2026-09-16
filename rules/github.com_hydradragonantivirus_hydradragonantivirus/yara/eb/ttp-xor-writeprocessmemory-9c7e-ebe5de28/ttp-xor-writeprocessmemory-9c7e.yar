rule TTP_XOR_WriteProcessMemory_9c7e {
  strings:
    $key_9c7e = { cb 0c [2] f9 2e [2] ff 1b [2] d1 1b [2] ee 07 }

  condition:
    any of them
}