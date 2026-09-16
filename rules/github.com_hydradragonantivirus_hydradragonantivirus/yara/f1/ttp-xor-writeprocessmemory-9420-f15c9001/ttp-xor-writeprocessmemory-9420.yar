rule TTP_XOR_WriteProcessMemory_9420 {
  strings:
    $key_9420 = { c3 52 [2] f1 70 [2] f7 45 [2] d9 45 [2] e6 59 }

  condition:
    any of them
}