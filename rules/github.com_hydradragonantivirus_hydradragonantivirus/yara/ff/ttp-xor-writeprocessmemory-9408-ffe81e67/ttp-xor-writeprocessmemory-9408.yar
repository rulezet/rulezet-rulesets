rule TTP_XOR_WriteProcessMemory_9408 {
  strings:
    $key_9408 = { c3 7a [2] f1 58 [2] f7 6d [2] d9 6d [2] e6 71 }

  condition:
    any of them
}