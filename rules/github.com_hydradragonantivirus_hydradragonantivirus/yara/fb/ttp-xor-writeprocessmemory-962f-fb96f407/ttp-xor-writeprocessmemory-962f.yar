rule TTP_XOR_WriteProcessMemory_962f {
  strings:
    $key_962f = { c1 5d [2] f3 7f [2] f5 4a [2] db 4a [2] e4 56 }

  condition:
    any of them
}