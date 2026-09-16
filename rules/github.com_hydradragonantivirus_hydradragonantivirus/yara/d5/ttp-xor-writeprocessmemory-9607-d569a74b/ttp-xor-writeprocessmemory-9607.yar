rule TTP_XOR_WriteProcessMemory_9607 {
  strings:
    $key_9607 = { c1 75 [2] f3 57 [2] f5 62 [2] db 62 [2] e4 7e }

  condition:
    any of them
}