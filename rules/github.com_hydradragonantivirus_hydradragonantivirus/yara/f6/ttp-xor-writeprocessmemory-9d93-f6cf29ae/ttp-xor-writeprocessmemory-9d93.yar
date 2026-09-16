rule TTP_XOR_WriteProcessMemory_9d93 {
  strings:
    $key_9d93 = { ca e1 [2] f8 c3 [2] fe f6 [2] d0 f6 [2] ef ea }

  condition:
    any of them
}