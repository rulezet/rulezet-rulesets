rule TTP_XOR_WriteProcessMemory_db0b {
  strings:
    $key_db0b = { 8c 79 [2] be 5b [2] b8 6e [2] 96 6e [2] a9 72 }

  condition:
    any of them
}