rule TTP_XOR_WriteProcessMemory_be39 {
  strings:
    $key_be39 = { e9 4b [2] db 69 [2] dd 5c [2] f3 5c [2] cc 40 }

  condition:
    any of them
}