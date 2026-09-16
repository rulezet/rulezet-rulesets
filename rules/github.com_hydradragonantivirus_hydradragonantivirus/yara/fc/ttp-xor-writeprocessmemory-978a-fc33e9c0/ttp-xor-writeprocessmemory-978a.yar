rule TTP_XOR_WriteProcessMemory_978a {
  strings:
    $key_978a = { c0 f8 [2] f2 da [2] f4 ef [2] da ef [2] e5 f3 }

  condition:
    any of them
}