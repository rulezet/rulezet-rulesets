rule TTP_XOR_WriteProcessMemory_9bd1 {
  strings:
    $key_9bd1 = { cc a3 [2] fe 81 [2] f8 b4 [2] d6 b4 [2] e9 a8 }

  condition:
    any of them
}