rule TTP_XOR_WriteProcessMemory_7e8a {
  strings:
    $key_7e8a = { 29 f8 [2] 1b da [2] 1d ef [2] 33 ef [2] 0c f3 }

  condition:
    any of them
}