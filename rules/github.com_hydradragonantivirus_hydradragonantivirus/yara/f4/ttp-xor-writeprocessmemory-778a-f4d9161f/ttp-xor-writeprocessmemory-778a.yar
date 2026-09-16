rule TTP_XOR_WriteProcessMemory_778a {
  strings:
    $key_778a = { 20 f8 [2] 12 da [2] 14 ef [2] 3a ef [2] 05 f3 }

  condition:
    any of them
}