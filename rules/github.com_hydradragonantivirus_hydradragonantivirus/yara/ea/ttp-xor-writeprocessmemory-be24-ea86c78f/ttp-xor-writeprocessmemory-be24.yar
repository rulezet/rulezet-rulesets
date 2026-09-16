rule TTP_XOR_WriteProcessMemory_be24 {
  strings:
    $key_be24 = { e9 56 [2] db 74 [2] dd 41 [2] f3 41 [2] cc 5d }

  condition:
    any of them
}