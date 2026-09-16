rule TTP_XOR_WriteProcessMemory_be43 {
  strings:
    $key_be43 = { e9 31 [2] db 13 [2] dd 26 [2] f3 26 [2] cc 3a }

  condition:
    any of them
}