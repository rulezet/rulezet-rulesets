rule TTP_XOR_WriteProcessMemory_9df4 {
  strings:
    $key_9df4 = { ca 86 [2] f8 a4 [2] fe 91 [2] d0 91 [2] ef 8d }

  condition:
    any of them
}