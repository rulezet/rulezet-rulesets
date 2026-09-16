rule TTP_XOR_WriteProcessMemory_906d {
  strings:
    $key_906d = { c7 1f [2] f5 3d [2] f3 08 [2] dd 08 [2] e2 14 }

  condition:
    any of them
}