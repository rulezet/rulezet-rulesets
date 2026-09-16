rule TTP_XOR_WriteProcessMemory_9076 {
  strings:
    $key_9076 = { c7 04 [2] f5 26 [2] f3 13 [2] dd 13 [2] e2 0f }

  condition:
    any of them
}