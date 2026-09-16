rule TTP_XOR_WriteProcessMemory_9459 {
  strings:
    $key_9459 = { c3 2b [2] f1 09 [2] f7 3c [2] d9 3c [2] e6 20 }

  condition:
    any of them
}