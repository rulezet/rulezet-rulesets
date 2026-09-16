rule TTP_XOR_WriteProcessMemory_9c0a {
  strings:
    $key_9c0a = { cb 78 [2] f9 5a [2] ff 6f [2] d1 6f [2] ee 73 }

  condition:
    any of them
}