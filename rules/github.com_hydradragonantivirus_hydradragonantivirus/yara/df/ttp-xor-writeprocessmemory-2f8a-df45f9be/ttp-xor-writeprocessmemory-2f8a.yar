rule TTP_XOR_WriteProcessMemory_2f8a {
  strings:
    $key_2f8a = { 78 f8 [2] 4a da [2] 4c ef [2] 62 ef [2] 5d f3 }

  condition:
    any of them
}