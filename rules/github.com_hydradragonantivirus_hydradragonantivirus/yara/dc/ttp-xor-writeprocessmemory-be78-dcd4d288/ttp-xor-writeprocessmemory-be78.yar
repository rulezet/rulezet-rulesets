rule TTP_XOR_WriteProcessMemory_be78 {
  strings:
    $key_be78 = { e9 0a [2] db 28 [2] dd 1d [2] f3 1d [2] cc 01 }

  condition:
    any of them
}