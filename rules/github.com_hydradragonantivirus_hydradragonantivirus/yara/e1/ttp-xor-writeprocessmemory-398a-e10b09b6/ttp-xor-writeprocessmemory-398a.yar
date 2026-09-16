rule TTP_XOR_WriteProcessMemory_398a {
  strings:
    $key_398a = { 6e f8 [2] 5c da [2] 5a ef [2] 74 ef [2] 4b f3 }

  condition:
    any of them
}