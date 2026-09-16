rule TTP_XOR_WriteProcessMemory_9486 {
  strings:
    $key_9486 = { c3 f4 [2] f1 d6 [2] f7 e3 [2] d9 e3 [2] e6 ff }

  condition:
    any of them
}