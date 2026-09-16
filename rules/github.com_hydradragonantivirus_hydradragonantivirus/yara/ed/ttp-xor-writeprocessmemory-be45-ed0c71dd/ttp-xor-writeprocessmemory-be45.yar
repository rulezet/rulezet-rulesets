rule TTP_XOR_WriteProcessMemory_be45 {
  strings:
    $key_be45 = { e9 37 [2] db 15 [2] dd 20 [2] f3 20 [2] cc 3c }

  condition:
    any of them
}