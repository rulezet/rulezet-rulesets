rule TTP_XOR_WriteProcessMemory_be70 {
  strings:
    $key_be70 = { e9 02 [2] db 20 [2] dd 15 [2] f3 15 [2] cc 09 }

  condition:
    any of them
}