rule TTP_XOR_WriteProcessMemory_818b {
  strings:
    $key_818b = { d6 f9 [2] e4 db [2] e2 ee [2] cc ee [2] f3 f2 }

  condition:
    any of them
}