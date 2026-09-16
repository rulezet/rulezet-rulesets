rule TTP_XOR_WriteProcessMemory_0f8a {
  strings:
    $key_0f8a = { 58 f8 [2] 6a da [2] 6c ef [2] 42 ef [2] 7d f3 }

  condition:
    any of them
}