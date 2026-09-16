rule TTP_XOR_WriteProcessMemory_902f {
  strings:
    $key_902f = { c7 5d [2] f5 7f [2] f3 4a [2] dd 4a [2] e2 56 }

  condition:
    any of them
}