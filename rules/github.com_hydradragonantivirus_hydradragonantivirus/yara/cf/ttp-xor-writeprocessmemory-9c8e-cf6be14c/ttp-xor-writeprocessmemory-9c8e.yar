rule TTP_XOR_WriteProcessMemory_9c8e {
  strings:
    $key_9c8e = { cb fc [2] f9 de [2] ff eb [2] d1 eb [2] ee f7 }

  condition:
    any of them
}