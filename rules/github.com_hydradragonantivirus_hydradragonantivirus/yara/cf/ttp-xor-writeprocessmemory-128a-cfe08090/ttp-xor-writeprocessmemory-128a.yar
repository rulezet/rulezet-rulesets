rule TTP_XOR_WriteProcessMemory_128a {
  strings:
    $key_128a = { 45 f8 [2] 77 da [2] 71 ef [2] 5f ef [2] 60 f3 }

  condition:
    any of them
}