rule TTP_XOR_WriteProcessMemory_be3b {
  strings:
    $key_be3b = { e9 49 [2] db 6b [2] dd 5e [2] f3 5e [2] cc 42 }

  condition:
    any of them
}