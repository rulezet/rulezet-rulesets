rule TTP_XOR_WriteProcessMemory_9034 {
  strings:
    $key_9034 = { c7 46 [2] f5 64 [2] f3 51 [2] dd 51 [2] e2 4d }

  condition:
    any of them
}