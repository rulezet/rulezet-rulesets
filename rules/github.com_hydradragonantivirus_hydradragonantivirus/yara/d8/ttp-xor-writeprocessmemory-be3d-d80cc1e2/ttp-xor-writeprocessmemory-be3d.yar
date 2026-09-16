rule TTP_XOR_WriteProcessMemory_be3d {
  strings:
    $key_be3d = { e9 4f [2] db 6d [2] dd 58 [2] f3 58 [2] cc 44 }

  condition:
    any of them
}