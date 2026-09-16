rule TTP_XOR_WriteProcessMemory_9be1 {
  strings:
    $key_9be1 = { cc 93 [2] fe b1 [2] f8 84 [2] d6 84 [2] e9 98 }

  condition:
    any of them
}