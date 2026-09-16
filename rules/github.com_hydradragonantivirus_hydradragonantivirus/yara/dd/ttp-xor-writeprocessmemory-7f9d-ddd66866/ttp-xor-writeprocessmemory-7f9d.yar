rule TTP_XOR_WriteProcessMemory_7f9d {
  strings:
    $key_7f9d = { 28 ef [2] 1a cd [2] 1c f8 [2] 32 f8 [2] 0d e4 }

  condition:
    any of them
}