rule TTP_XOR_WriteProcessMemory_9b1a {
  strings:
    $key_9b1a = { cc 68 [2] fe 4a [2] f8 7f [2] d6 7f [2] e9 63 }

  condition:
    any of them
}