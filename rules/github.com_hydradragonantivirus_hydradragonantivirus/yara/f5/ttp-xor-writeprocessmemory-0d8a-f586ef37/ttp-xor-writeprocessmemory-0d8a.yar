rule TTP_XOR_WriteProcessMemory_0d8a {
  strings:
    $key_0d8a = { 5a f8 [2] 68 da [2] 6e ef [2] 40 ef [2] 7f f3 }

  condition:
    any of them
}