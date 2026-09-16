rule TTP_XOR_WriteProcessMemory_976d {
  strings:
    $key_976d = { c0 1f [2] f2 3d [2] f4 08 [2] da 08 [2] e5 14 }

  condition:
    any of them
}