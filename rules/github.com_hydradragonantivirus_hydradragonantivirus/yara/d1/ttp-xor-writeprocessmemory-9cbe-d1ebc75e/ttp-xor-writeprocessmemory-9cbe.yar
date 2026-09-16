rule TTP_XOR_WriteProcessMemory_9cbe {
  strings:
    $key_9cbe = { cb cc [2] f9 ee [2] ff db [2] d1 db [2] ee c7 }

  condition:
    any of them
}