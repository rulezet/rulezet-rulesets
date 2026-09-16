rule TTP_XOR_WriteProcessMemory_db3b {
  strings:
    $key_db3b = { 8c 49 [2] be 6b [2] b8 5e [2] 96 5e [2] a9 42 }

  condition:
    any of them
}