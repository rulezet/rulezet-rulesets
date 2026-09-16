rule TTP_XOR_WriteProcessMemory_9c70 {
  strings:
    $key_9c70 = { cb 02 [2] f9 20 [2] ff 15 [2] d1 15 [2] ee 09 }

  condition:
    any of them
}