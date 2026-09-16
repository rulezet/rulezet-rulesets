rule TTP_XOR_WriteProcessMemory_9586 {
  strings:
    $key_9586 = { c2 f4 [2] f0 d6 [2] f6 e3 [2] d8 e3 [2] e7 ff }

  condition:
    any of them
}