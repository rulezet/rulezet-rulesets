rule TTP_XOR_WriteProcessMemory_828b {
  strings:
    $key_828b = { d5 f9 [2] e7 db [2] e1 ee [2] cf ee [2] f0 f2 }

  condition:
    any of them
}