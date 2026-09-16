rule TTP_XOR_WriteProcessMemory_be60 {
  strings:
    $key_be60 = { e9 12 [2] db 30 [2] dd 05 [2] f3 05 [2] cc 19 }

  condition:
    any of them
}