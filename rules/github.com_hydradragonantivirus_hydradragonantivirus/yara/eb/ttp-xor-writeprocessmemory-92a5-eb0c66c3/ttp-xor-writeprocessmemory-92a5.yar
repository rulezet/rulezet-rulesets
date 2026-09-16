rule TTP_XOR_WriteProcessMemory_92a5 {
  strings:
    $key_92a5 = { c5 d7 [2] f7 f5 [2] f1 c0 [2] df c0 [2] e0 dc }

  condition:
    any of them
}