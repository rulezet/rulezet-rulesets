rule TTP_XOR_WriteProcessMemory_9c28 {
  strings:
    $key_9c28 = { cb 5a [2] f9 78 [2] ff 4d [2] d1 4d [2] ee 51 }

  condition:
    any of them
}