rule TTP_XOR_WriteProcessMemory_8329 {
  strings:
    $key_8329 = { d4 5b [2] e6 79 [2] e0 4c [2] ce 4c [2] f1 50 }

  condition:
    any of them
}