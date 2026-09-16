rule TTP_XOR_WriteProcessMemory_934f {
  strings:
    $key_934f = { c4 3d [2] f6 1f [2] f0 2a [2] de 2a [2] e1 36 }

  condition:
    any of them
}