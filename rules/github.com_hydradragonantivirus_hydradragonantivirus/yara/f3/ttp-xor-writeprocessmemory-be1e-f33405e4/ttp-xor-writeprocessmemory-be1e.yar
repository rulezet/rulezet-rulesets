rule TTP_XOR_WriteProcessMemory_be1e {
  strings:
    $key_be1e = { e9 6c [2] db 4e [2] dd 7b [2] f3 7b [2] cc 67 }

  condition:
    any of them
}