rule TTP_XOR_WriteProcessMemory_9c31 {
  strings:
    $key_9c31 = { cb 43 [2] f9 61 [2] ff 54 [2] d1 54 [2] ee 48 }

  condition:
    any of them
}