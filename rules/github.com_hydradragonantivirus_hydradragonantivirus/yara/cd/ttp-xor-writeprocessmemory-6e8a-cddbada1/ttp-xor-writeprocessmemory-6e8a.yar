rule TTP_XOR_WriteProcessMemory_6e8a {
  strings:
    $key_6e8a = { 39 f8 [2] 0b da [2] 0d ef [2] 23 ef [2] 1c f3 }

  condition:
    any of them
}