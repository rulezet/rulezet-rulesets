rule TTP_XOR_WriteProcessMemory_be69 {
  strings:
    $key_be69 = { e9 1b [2] db 39 [2] dd 0c [2] f3 0c [2] cc 10 }

  condition:
    any of them
}