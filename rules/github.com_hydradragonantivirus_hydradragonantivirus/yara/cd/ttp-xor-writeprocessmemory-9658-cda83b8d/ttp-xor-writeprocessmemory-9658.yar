rule TTP_XOR_WriteProcessMemory_9658 {
  strings:
    $key_9658 = { c1 2a [2] f3 08 [2] f5 3d [2] db 3d [2] e4 21 }

  condition:
    any of them
}