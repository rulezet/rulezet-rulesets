rule TTP_XOR_WriteProcessMemory_be28 {
  strings:
    $key_be28 = { e9 5a [2] db 78 [2] dd 4d [2] f3 4d [2] cc 51 }

  condition:
    any of them
}