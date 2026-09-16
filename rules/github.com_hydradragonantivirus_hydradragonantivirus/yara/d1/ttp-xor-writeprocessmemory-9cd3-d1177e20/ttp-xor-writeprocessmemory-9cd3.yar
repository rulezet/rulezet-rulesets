rule TTP_XOR_WriteProcessMemory_9cd3 {
  strings:
    $key_9cd3 = { cb a1 [2] f9 83 [2] ff b6 [2] d1 b6 [2] ee aa }

  condition:
    any of them
}