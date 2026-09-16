rule TTP_XOR_WriteProcessMemory_9d0e {
  strings:
    $key_9d0e = { ca 7c [2] f8 5e [2] fe 6b [2] d0 6b [2] ef 77 }

  condition:
    any of them
}