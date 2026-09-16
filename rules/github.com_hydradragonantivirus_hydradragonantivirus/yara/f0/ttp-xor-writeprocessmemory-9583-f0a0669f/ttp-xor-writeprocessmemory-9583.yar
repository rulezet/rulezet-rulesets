rule TTP_XOR_WriteProcessMemory_9583 {
  strings:
    $key_9583 = { c2 f1 [2] f0 d3 [2] f6 e6 [2] d8 e6 [2] e7 fa }

  condition:
    any of them
}