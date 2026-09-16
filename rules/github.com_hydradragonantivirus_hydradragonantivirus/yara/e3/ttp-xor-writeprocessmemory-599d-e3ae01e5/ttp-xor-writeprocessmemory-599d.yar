rule TTP_XOR_WriteProcessMemory_599d {
  strings:
    $key_599d = { 0e ef [2] 3c cd [2] 3a f8 [2] 14 f8 [2] 2b e4 }

  condition:
    any of them
}