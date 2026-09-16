rule TTP_XOR_WriteProcessMemory_1d9d {
  strings:
    $key_1d9d = { 4a ef [2] 78 cd [2] 7e f8 [2] 50 f8 [2] 6f e4 }

  condition:
    any of them
}