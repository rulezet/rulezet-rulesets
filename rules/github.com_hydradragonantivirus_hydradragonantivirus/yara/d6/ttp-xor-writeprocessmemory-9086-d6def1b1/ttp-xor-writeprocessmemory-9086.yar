rule TTP_XOR_WriteProcessMemory_9086 {
  strings:
    $key_9086 = { c7 f4 [2] f5 d6 [2] f3 e3 [2] dd e3 [2] e2 ff }

  condition:
    any of them
}