rule TTP_XOR_WriteProcessMemory_9cd4 {
  strings:
    $key_9cd4 = { cb a6 [2] f9 84 [2] ff b1 [2] d1 b1 [2] ee ad }

  condition:
    any of them
}