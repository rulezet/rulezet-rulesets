rule TTP_XOR_WriteProcessMemory_9628 {
  strings:
    $key_9628 = { c1 5a [2] f3 78 [2] f5 4d [2] db 4d [2] e4 51 }

  condition:
    any of them
}