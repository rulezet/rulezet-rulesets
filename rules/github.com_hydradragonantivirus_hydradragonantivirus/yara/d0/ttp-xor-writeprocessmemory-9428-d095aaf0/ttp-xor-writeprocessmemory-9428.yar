rule TTP_XOR_WriteProcessMemory_9428 {
  strings:
    $key_9428 = { c3 5a [2] f1 78 [2] f7 4d [2] d9 4d [2] e6 51 }

  condition:
    any of them
}