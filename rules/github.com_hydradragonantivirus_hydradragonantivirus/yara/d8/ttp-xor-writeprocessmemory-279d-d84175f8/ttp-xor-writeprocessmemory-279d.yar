rule TTP_XOR_WriteProcessMemory_279d {
  strings:
    $key_279d = { 70 ef [2] 42 cd [2] 44 f8 [2] 6a f8 [2] 55 e4 }

  condition:
    any of them
}