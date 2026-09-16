rule TTP_XOR_WriteProcessMemory_9023 {
  strings:
    $key_9023 = { c7 51 [2] f5 73 [2] f3 46 [2] dd 46 [2] e2 5a }

  condition:
    any of them
}