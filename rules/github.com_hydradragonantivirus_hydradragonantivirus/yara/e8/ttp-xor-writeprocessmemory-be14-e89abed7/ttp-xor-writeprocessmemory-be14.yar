rule TTP_XOR_WriteProcessMemory_be14 {
  strings:
    $key_be14 = { e9 66 [2] db 44 [2] dd 71 [2] f3 71 [2] cc 6d }

  condition:
    any of them
}