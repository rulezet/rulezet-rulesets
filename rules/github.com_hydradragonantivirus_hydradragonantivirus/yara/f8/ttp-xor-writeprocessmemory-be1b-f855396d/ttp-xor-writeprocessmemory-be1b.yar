rule TTP_XOR_WriteProcessMemory_be1b {
  strings:
    $key_be1b = { e9 69 [2] db 4b [2] dd 7e [2] f3 7e [2] cc 62 }

  condition:
    any of them
}