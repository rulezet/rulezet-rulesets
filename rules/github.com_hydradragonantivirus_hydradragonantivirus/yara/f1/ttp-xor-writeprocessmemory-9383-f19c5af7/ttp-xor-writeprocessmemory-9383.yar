rule TTP_XOR_WriteProcessMemory_9383 {
  strings:
    $key_9383 = { c4 f1 [2] f6 d3 [2] f0 e6 [2] de e6 [2] e1 fa }

  condition:
    any of them
}