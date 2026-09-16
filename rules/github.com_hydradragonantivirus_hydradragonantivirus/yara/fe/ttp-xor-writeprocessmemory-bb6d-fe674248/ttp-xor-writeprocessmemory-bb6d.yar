rule TTP_XOR_WriteProcessMemory_bb6d {
  strings:
    $key_bb6d = { ec 1f [2] de 3d [2] d8 08 [2] f6 08 [2] c9 14 }

  condition:
    any of them
}