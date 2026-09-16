rule TTP_XOR_WriteProcessMemory_901f {
  strings:
    $key_901f = { c7 6d [2] f5 4f [2] f3 7a [2] dd 7a [2] e2 66 }

  condition:
    any of them
}