rule TTP_XOR_WriteProcessMemory_930f {
  strings:
    $key_930f = { c4 7d [2] f6 5f [2] f0 6a [2] de 6a [2] e1 76 }

  condition:
    any of them
}