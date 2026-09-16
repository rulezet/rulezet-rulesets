rule TTP_XOR_WriteProcessMemory_5d9d {
  strings:
    $key_5d9d = { 0a ef [2] 38 cd [2] 3e f8 [2] 10 f8 [2] 2f e4 }

  condition:
    any of them
}