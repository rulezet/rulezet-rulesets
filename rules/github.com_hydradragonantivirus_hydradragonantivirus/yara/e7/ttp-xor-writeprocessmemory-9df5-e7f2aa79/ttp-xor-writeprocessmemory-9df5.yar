rule TTP_XOR_WriteProcessMemory_9df5 {
  strings:
    $key_9df5 = { ca 87 [2] f8 a5 [2] fe 90 [2] d0 90 [2] ef 8c }

  condition:
    any of them
}