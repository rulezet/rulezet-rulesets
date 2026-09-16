rule TTP_XOR_WriteProcessMemory_9bf2 {
  strings:
    $key_9bf2 = { cc 80 [2] fe a2 [2] f8 97 [2] d6 97 [2] e9 8b }

  condition:
    any of them
}