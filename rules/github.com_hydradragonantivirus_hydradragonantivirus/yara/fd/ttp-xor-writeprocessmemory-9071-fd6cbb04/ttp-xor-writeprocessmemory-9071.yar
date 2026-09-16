rule TTP_XOR_WriteProcessMemory_9071 {
  strings:
    $key_9071 = { c7 03 [2] f5 21 [2] f3 14 [2] dd 14 [2] e2 08 }

  condition:
    any of them
}