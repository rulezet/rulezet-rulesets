rule TTP_XOR_WriteProcessMemory_be2e {
  strings:
    $key_be2e = { e9 5c [2] db 7e [2] dd 4b [2] f3 4b [2] cc 57 }

  condition:
    any of them
}