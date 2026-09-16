rule TTP_XOR_WriteProcessMemory_9c01 {
  strings:
    $key_9c01 = { cb 73 [2] f9 51 [2] ff 64 [2] d1 64 [2] ee 78 }

  condition:
    any of them
}