rule TTP_XOR_WriteProcessMemory_159d {
  strings:
    $key_159d = { 42 ef [2] 70 cd [2] 76 f8 [2] 58 f8 [2] 67 e4 }

  condition:
    any of them
}