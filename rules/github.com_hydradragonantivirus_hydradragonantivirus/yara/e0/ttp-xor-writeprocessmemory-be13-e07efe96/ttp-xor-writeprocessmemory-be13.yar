rule TTP_XOR_WriteProcessMemory_be13 {
  strings:
    $key_be13 = { e9 61 [2] db 43 [2] dd 76 [2] f3 76 [2] cc 6a }

  condition:
    any of them
}