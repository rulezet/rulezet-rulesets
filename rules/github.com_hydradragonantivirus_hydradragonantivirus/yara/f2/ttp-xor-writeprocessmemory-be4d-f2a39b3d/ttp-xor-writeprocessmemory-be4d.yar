rule TTP_XOR_WriteProcessMemory_be4d {
  strings:
    $key_be4d = { e9 3f [2] db 1d [2] dd 28 [2] f3 28 [2] cc 34 }

  condition:
    any of them
}