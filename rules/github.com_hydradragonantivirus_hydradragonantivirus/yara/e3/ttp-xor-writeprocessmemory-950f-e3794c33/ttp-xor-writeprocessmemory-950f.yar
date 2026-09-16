rule TTP_XOR_WriteProcessMemory_950f {
  strings:
    $key_950f = { c2 7d [2] f0 5f [2] f6 6a [2] d8 6a [2] e7 76 }

  condition:
    any of them
}