rule TTP_XOR_WriteProcessMemory_9672 {
  strings:
    $key_9672 = { c1 00 [2] f3 22 [2] f5 17 [2] db 17 [2] e4 0b }

  condition:
    any of them
}