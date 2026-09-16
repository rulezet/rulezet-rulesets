rule TTP_XOR_WriteProcessMemory_be35 {
  strings:
    $key_be35 = { e9 47 [2] db 65 [2] dd 50 [2] f3 50 [2] cc 4c }

  condition:
    any of them
}