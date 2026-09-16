rule TTP_XOR_WriteProcessMemory_ff9d {
  strings:
    $key_ff9d = { a8 ef [2] 9a cd [2] 9c f8 [2] b2 f8 [2] 8d e4 }

  condition:
    any of them
}