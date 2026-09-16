rule TTP_XOR_WriteProcessMemory_3f9d {
  strings:
    $key_3f9d = { 68 ef [2] 5a cd [2] 5c f8 [2] 72 f8 [2] 4d e4 }

  condition:
    any of them
}