rule TTP_XOR_WriteProcessMemory_9475 {
  strings:
    $key_9475 = { c3 07 [2] f1 25 [2] f7 10 [2] d9 10 [2] e6 0c }

  condition:
    any of them
}