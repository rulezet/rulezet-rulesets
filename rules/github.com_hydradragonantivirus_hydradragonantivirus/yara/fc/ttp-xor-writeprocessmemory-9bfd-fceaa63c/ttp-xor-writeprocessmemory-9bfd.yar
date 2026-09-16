rule TTP_XOR_WriteProcessMemory_9bfd {
  strings:
    $key_9bfd = { cc 8f [2] fe ad [2] f8 98 [2] d6 98 [2] e9 84 }

  condition:
    any of them
}