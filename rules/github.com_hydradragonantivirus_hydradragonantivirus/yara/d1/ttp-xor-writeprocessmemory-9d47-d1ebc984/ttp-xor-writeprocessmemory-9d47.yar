rule TTP_XOR_WriteProcessMemory_9d47 {
  strings:
    $key_9d47 = { ca 35 [2] f8 17 [2] fe 22 [2] d0 22 [2] ef 3e }

  condition:
    any of them
}