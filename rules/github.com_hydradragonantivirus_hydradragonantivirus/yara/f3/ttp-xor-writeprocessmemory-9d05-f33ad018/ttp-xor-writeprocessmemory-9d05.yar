rule TTP_XOR_WriteProcessMemory_9d05 {
  strings:
    $key_9d05 = { ca 77 [2] f8 55 [2] fe 60 [2] d0 60 [2] ef 7c }

  condition:
    any of them
}