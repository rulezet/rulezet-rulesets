rule TTP_XOR_WriteProcessMemory_951f {
  strings:
    $key_951f = { c2 6d [2] f0 4f [2] f6 7a [2] d8 7a [2] e7 66 }

  condition:
    any of them
}