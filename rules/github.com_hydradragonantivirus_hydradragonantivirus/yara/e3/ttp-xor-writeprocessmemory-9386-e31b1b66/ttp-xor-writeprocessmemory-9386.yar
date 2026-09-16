rule TTP_XOR_WriteProcessMemory_9386 {
  strings:
    $key_9386 = { c4 f4 [2] f6 d6 [2] f0 e3 [2] de e3 [2] e1 ff }

  condition:
    any of them
}