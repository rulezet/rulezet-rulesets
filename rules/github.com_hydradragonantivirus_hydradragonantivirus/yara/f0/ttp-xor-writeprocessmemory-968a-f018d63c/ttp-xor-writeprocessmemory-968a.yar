rule TTP_XOR_WriteProcessMemory_968a {
  strings:
    $key_968a = { c1 f8 [2] f3 da [2] f5 ef [2] db ef [2] e4 f3 }

  condition:
    any of them
}