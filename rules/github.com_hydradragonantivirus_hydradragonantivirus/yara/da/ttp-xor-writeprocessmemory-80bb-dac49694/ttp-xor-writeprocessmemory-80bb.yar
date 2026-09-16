rule TTP_XOR_WriteProcessMemory_80bb {
  strings:
    $key_80bb = { d7 c9 [2] e5 eb [2] e3 de [2] cd de [2] f2 c2 }

  condition:
    any of them
}