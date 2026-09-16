rule TTP_XOR_WriteProcessMemory_9439 {
  strings:
    $key_9439 = { c3 4b [2] f1 69 [2] f7 5c [2] d9 5c [2] e6 40 }

  condition:
    any of them
}