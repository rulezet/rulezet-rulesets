rule TTP_XOR_WriteProcessMemory_9df1 {
  strings:
    $key_9df1 = { ca 83 [2] f8 a1 [2] fe 94 [2] d0 94 [2] ef 88 }

  condition:
    any of them
}