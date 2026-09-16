rule TTP_XOR_WriteProcessMemory_5a9d {
  strings:
    $key_5a9d = { 0d ef [2] 3f cd [2] 39 f8 [2] 17 f8 [2] 28 e4 }

  condition:
    any of them
}