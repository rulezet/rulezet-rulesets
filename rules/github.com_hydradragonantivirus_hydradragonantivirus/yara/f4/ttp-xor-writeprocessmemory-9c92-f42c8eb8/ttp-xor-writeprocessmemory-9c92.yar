rule TTP_XOR_WriteProcessMemory_9c92 {
  strings:
    $key_9c92 = { cb e0 [2] f9 c2 [2] ff f7 [2] d1 f7 [2] ee eb }

  condition:
    any of them
}