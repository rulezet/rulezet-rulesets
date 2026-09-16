rule TTP_XOR_WriteProcessMemory_be21 {
  strings:
    $key_be21 = { e9 53 [2] db 71 [2] dd 44 [2] f3 44 [2] cc 58 }

  condition:
    any of them
}