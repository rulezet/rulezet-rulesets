rule TTP_XOR_WriteProcessMemory_9bf3 {
  strings:
    $key_9bf3 = { cc 81 [2] fe a3 [2] f8 96 [2] d6 96 [2] e9 8a }

  condition:
    any of them
}