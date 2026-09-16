rule TTP_XOR_WriteProcessMemory_638a {
  strings:
    $key_638a = { 34 f8 [2] 06 da [2] 00 ef [2] 2e ef [2] 11 f3 }

  condition:
    any of them
}