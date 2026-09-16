rule TTP_XOR_WriteProcessMemory_8297 {
  strings:
    $key_8297 = { d5 e5 [2] e7 c7 [2] e1 f2 [2] cf f2 [2] f0 ee }

  condition:
    any of them
}