rule TTP_XOR_WriteProcessMemory_189d {
  strings:
    $key_189d = { 4f ef [2] 7d cd [2] 7b f8 [2] 55 f8 [2] 6a e4 }

  condition:
    any of them
}