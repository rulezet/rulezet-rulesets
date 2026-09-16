rule TTP_XOR_WriteProcessMemory_9422 {
  strings:
    $key_9422 = { c3 50 [2] f1 72 [2] f7 47 [2] d9 47 [2] e6 5b }

  condition:
    any of them
}