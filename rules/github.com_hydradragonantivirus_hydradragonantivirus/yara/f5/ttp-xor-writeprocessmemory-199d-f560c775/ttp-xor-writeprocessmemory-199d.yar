rule TTP_XOR_WriteProcessMemory_199d {
  strings:
    $key_199d = { 4e ef [2] 7c cd [2] 7a f8 [2] 54 f8 [2] 6b e4 }

  condition:
    any of them
}