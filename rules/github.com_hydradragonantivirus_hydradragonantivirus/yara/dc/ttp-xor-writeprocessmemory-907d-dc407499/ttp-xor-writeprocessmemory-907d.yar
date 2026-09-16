rule TTP_XOR_WriteProcessMemory_907d {
  strings:
    $key_907d = { c7 0f [2] f5 2d [2] f3 18 [2] dd 18 [2] e2 04 }

  condition:
    any of them
}