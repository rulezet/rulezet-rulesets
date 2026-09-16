rule TTP_XOR_WriteProcessMemory_818a {
  strings:
    $key_818a = { d6 f8 [2] e4 da [2] e2 ef [2] cc ef [2] f3 f3 }

  condition:
    any of them
}