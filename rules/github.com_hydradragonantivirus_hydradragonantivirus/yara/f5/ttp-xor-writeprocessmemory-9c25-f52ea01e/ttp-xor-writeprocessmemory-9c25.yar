rule TTP_XOR_WriteProcessMemory_9c25 {
  strings:
    $key_9c25 = { cb 57 [2] f9 75 [2] ff 40 [2] d1 40 [2] ee 5c }

  condition:
    any of them
}