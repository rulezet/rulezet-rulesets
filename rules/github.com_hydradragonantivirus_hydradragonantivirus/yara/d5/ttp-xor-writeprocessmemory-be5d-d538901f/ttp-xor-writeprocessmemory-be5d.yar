rule TTP_XOR_WriteProcessMemory_be5d {
  strings:
    $key_be5d = { e9 2f [2] db 0d [2] dd 38 [2] f3 38 [2] cc 24 }

  condition:
    any of them
}