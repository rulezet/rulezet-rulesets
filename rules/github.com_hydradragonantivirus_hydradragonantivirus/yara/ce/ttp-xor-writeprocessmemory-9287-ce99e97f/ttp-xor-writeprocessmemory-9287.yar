rule TTP_XOR_WriteProcessMemory_9287 {
  strings:
    $key_9287 = { c5 f5 [2] f7 d7 [2] f1 e2 [2] df e2 [2] e0 fe }

  condition:
    any of them
}