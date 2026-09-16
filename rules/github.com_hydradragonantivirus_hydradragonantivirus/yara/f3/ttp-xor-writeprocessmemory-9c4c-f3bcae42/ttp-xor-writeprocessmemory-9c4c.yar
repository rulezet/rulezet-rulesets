rule TTP_XOR_WriteProcessMemory_9c4c {
  strings:
    $key_9c4c = { cb 3e [2] f9 1c [2] ff 29 [2] d1 29 [2] ee 35 }

  condition:
    any of them
}