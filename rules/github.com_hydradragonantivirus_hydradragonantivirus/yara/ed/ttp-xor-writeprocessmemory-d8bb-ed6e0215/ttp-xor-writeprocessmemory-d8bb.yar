rule TTP_XOR_WriteProcessMemory_d8bb {
  strings:
    $key_d8bb = { 8f c9 [2] bd eb [2] bb de [2] 95 de [2] aa c2 }

  condition:
    any of them
}