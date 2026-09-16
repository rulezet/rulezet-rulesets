rule TTP_XOR_WriteProcessMemory_9c6f {
  strings:
    $key_9c6f = { cb 1d [2] f9 3f [2] ff 0a [2] d1 0a [2] ee 16 }

  condition:
    any of them
}