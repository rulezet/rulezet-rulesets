rule TTP_XOR_WriteProcessMemory_a98a {
  strings:
    $key_a98a = { fe f8 [2] cc da [2] ca ef [2] e4 ef [2] db f3 }

  condition:
    any of them
}