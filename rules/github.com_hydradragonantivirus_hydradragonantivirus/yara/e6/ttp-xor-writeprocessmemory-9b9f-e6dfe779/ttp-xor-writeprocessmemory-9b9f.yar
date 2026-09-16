rule TTP_XOR_WriteProcessMemory_9b9f {
  strings:
    $key_9b9f = { cc ed [2] fe cf [2] f8 fa [2] d6 fa [2] e9 e6 }

  condition:
    any of them
}