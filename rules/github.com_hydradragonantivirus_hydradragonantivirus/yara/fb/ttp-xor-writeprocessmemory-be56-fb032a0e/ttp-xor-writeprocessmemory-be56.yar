rule TTP_XOR_WriteProcessMemory_be56 {
  strings:
    $key_be56 = { e9 24 [2] db 06 [2] dd 33 [2] f3 33 [2] cc 2f }

  condition:
    any of them
}