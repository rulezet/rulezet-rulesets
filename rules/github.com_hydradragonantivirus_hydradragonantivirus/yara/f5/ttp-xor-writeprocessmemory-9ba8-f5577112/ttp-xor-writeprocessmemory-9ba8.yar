rule TTP_XOR_WriteProcessMemory_9ba8 {
  strings:
    $key_9ba8 = { cc da [2] fe f8 [2] f8 cd [2] d6 cd [2] e9 d1 }

  condition:
    any of them
}