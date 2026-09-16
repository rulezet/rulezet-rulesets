rule TTP_XOR_WriteProcessMemory_be44 {
  strings:
    $key_be44 = { e9 36 [2] db 14 [2] dd 21 [2] f3 21 [2] cc 3d }

  condition:
    any of them
}