rule TTP_XOR_WriteProcessMemory_9dcc {
  strings:
    $key_9dcc = { ca be [2] f8 9c [2] fe a9 [2] d0 a9 [2] ef b5 }

  condition:
    any of them
}