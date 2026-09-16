rule TTP_XOR_WriteProcessMemory_9468 {
  strings:
    $key_9468 = { c3 1a [2] f1 38 [2] f7 0d [2] d9 0d [2] e6 11 }

  condition:
    any of them
}