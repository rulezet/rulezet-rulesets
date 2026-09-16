rule TTP_XOR_WriteProcessMemory_fe8a {
  strings:
    $key_fe8a = { a9 f8 [2] 9b da [2] 9d ef [2] b3 ef [2] 8c f3 }

  condition:
    any of them
}