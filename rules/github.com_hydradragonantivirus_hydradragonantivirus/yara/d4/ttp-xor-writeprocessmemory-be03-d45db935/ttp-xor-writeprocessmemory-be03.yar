rule TTP_XOR_WriteProcessMemory_be03 {
  strings:
    $key_be03 = { e9 71 [2] db 53 [2] dd 66 [2] f3 66 [2] cc 7a }

  condition:
    any of them
}