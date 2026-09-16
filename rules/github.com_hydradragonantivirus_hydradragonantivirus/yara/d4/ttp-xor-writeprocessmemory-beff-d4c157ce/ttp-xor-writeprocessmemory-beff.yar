rule TTP_XOR_WriteProcessMemory_beff {
  strings:
    $key_beff = { e9 8d [2] db af [2] dd 9a [2] f3 9a [2] cc 86 }

  condition:
    any of them
}