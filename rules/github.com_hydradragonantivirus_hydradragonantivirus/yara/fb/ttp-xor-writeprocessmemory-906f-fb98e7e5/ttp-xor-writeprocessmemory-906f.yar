rule TTP_XOR_WriteProcessMemory_906f {
  strings:
    $key_906f = { c7 1d [2] f5 3f [2] f3 0a [2] dd 0a [2] e2 16 }

  condition:
    any of them
}