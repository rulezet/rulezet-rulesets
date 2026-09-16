rule TTP_XOR_WriteProcessMemory_0a8a {
  strings:
    $key_0a8a = { 5d f8 [2] 6f da [2] 69 ef [2] 47 ef [2] 78 f3 }

  condition:
    any of them
}