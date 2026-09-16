rule TTP_XOR_WriteProcessMemory_2f9d {
  strings:
    $key_2f9d = { 78 ef [2] 4a cd [2] 4c f8 [2] 62 f8 [2] 5d e4 }

  condition:
    any of them
}