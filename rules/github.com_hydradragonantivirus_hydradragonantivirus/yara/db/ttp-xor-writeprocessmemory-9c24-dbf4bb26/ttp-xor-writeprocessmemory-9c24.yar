rule TTP_XOR_WriteProcessMemory_9c24 {
  strings:
    $key_9c24 = { cb 56 [2] f9 74 [2] ff 41 [2] d1 41 [2] ee 5d }

  condition:
    any of them
}