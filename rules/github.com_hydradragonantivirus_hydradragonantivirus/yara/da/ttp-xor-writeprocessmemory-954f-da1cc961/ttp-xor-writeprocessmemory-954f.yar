rule TTP_XOR_WriteProcessMemory_954f {
  strings:
    $key_954f = { c2 3d [2] f0 1f [2] f6 2a [2] d8 2a [2] e7 36 }

  condition:
    any of them
}