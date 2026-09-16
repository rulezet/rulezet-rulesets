rule TTP_XOR_WriteProcessMemory_951d {
  strings:
    $key_951d = { c2 6f [2] f0 4d [2] f6 78 [2] d8 78 [2] e7 64 }

  condition:
    any of them
}