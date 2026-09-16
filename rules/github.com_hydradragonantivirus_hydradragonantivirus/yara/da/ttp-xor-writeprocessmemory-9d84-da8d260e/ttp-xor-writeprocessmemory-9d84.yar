rule TTP_XOR_WriteProcessMemory_9d84 {
  strings:
    $key_9d84 = { ca f6 [2] f8 d4 [2] fe e1 [2] d0 e1 [2] ef fd }

  condition:
    any of them
}