rule TTP_XOR_WriteProcessMemory_be61 {
  strings:
    $key_be61 = { e9 13 [2] db 31 [2] dd 04 [2] f3 04 [2] cc 18 }

  condition:
    any of them
}