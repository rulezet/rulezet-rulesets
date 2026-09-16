rule TTP_XOR_WriteProcessMemory_1d8a {
  strings:
    $key_1d8a = { 4a f8 [2] 78 da [2] 7e ef [2] 50 ef [2] 6f f3 }

  condition:
    any of them
}