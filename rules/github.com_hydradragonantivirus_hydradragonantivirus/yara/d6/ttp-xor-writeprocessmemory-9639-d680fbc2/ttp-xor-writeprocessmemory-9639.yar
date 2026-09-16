rule TTP_XOR_WriteProcessMemory_9639 {
  strings:
    $key_9639 = { c1 4b [2] f3 69 [2] f5 5c [2] db 5c [2] e4 40 }

  condition:
    any of them
}