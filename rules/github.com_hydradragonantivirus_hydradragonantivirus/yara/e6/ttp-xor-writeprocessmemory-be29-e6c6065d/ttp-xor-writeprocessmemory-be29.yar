rule TTP_XOR_WriteProcessMemory_be29 {
  strings:
    $key_be29 = { e9 5b [2] db 79 [2] dd 4c [2] f3 4c [2] cc 50 }

  condition:
    any of them
}